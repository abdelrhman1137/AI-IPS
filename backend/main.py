"""
main.py — FastAPI server for AIPS (AI Intrusion Prevention System).

Run with:  uvicorn main:app --reload --port 8000
(from the backend/ directory, as Administrator for live capture)
"""

import os
import sys
import asyncio
import json
import time
from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Ensure backend dir is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import auth as auth_module
import ids_engine as engine_module
from alertstore import store

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="AIPS", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── The running asyncio event loop (set on startup) ───────────────────────────
_loop: Optional[asyncio.AbstractEventLoop] = None

@app.on_event("startup")
async def _capture_loop():
    """Capture the uvicorn event loop so background threads can schedule coroutines."""
    global _loop
    _loop = asyncio.get_running_loop()
    # Wire the broadcast function into the engine with the real loop
    engine_module.engine.broadcast = manager.broadcast
    engine_module.set_loop(_loop)

    # Pre-warm interface detection in background so Start is near-instant
    import threading as _threading
    def _prewarm():
        try:
            engine_module.get_best_interface()
        except Exception:
            pass
    _threading.Thread(target=_prewarm, daemon=True).start()


# ── WebSocket Manager ──────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self._connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self._connections:
                self._connections.remove(ws)

    async def broadcast(self, msg: dict):
        data = json.dumps(msg)
        dead = []
        async with self._lock:
            for ws in list(self._connections):
                try:
                    await ws.send_text(data)
                except Exception:
                    dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)

manager = ConnectionManager()


# ── Auth routes ────────────────────────────────────────────────────────────────
@app.post("/api/auth/login", response_model=auth_module.TokenResponse)
def login(req: auth_module.LoginRequest):
    return auth_module.login(req)

@app.post("/api/auth/register")
def register(req: auth_module.RegisterRequest):
    return auth_module.register(req)


# ── Session / status ───────────────────────────────────────────────────────────
@app.get("/api/session")
def get_session(email: str = Depends(auth_module.get_current_user)):
    uptime   = time.time() - store.start_time if store.start_time else 0
    last_bps = store.get_throughput()[-1][1] if store.get_throughput() else 0
    return {
        "running":        engine_module.engine.running,
        "sim_active":     engine_module.engine.sim_active,
        "sniffer_ok":     engine_module.engine.sniffer_ok,
        "sniffer_error":  engine_module.receptor.sniffer_error or "",
        "raw_packets":    engine_module.receptor.raw_packet_count,
        "blocked_ips":    engine_module.fw_manager.get_blocked_list(),
        **store.get_stats(uptime, last_bps),
    }


# ── Engine controls ────────────────────────────────────────────────────────────
@app.post("/api/engine/start")
def start(email: str = Depends(auth_module.get_current_user)):
    import time as _time
    if _loop is None:
        raise HTTPException(status_code=503, detail="Server not ready yet")
    iface = engine_module.get_best_interface()
    if not iface:
        raise HTTPException(status_code=500, detail="No usable network interface found. Run backend as Administrator.")
    engine_module.start_engine(iface, _loop)
    # start_engine already sleeps 250ms for sniffer to spin up
    sniffer_ok  = engine_module.receptor.sniffer_running
    sniffer_err = engine_module.receptor.sniffer_error or ""
    return {
        "success":     True,
        "interface":   iface,
        "sniffer_ok":  sniffer_ok,
        "sniffer_error": sniffer_err,
    }

@app.post("/api/engine/stop")
def stop(email: str = Depends(auth_module.get_current_user)):
    engine_module.stop_engine()
    return {"success": True}

@app.post("/api/engine/clear")
def clear(email: str = Depends(auth_module.get_current_user)):
    engine_module.clear_session()
    return {"success": True}

class UnblockPayload(BaseModel):
    ip: str

@app.post("/api/engine/unblock")
def unblock(payload: UnblockPayload, email: str = Depends(auth_module.get_current_user)):
    """Remove the Windows Firewall IPS_BLOCK_{ip} rule for the given IP."""
    ip = payload.ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required")
    ok = engine_module.unblock_ip(ip)
    return {"success": ok, "ip": ip}

@app.post("/api/engine/selftest")
def self_test():
    if _loop is None:
        raise HTTPException(status_code=503, detail="Server not ready yet")
    fired, msg = engine_module.run_self_test(_loop)
    return {"fired": fired, "message": msg}


# ── Settings ───────────────────────────────────────────────────────────────────
class SettingsPayload(BaseModel):
    conf_threshold: Optional[float] = None
    guard:          Optional[int]   = None
    auto_block:     Optional[bool]  = None
    webhook_url:    Optional[str]   = None

@app.get("/api/settings")
def get_settings(email: str = Depends(auth_module.get_current_user)):
    s = engine_module.settings
    return {
        "conf_threshold": s.conf_threshold,
        "guard":          s.guard,
        "auto_block":     s.auto_block,
        "webhook_url":    s.webhook_url,
    }

@app.post("/api/settings")
def update_settings(payload: SettingsPayload, email: str = Depends(auth_module.get_current_user)):
    s = engine_module.settings
    if payload.conf_threshold is not None:
        s.conf_threshold = max(0.40, min(0.99, payload.conf_threshold))
    if payload.guard is not None:
        s.guard = max(1, min(5, payload.guard))
    if payload.auto_block is not None:
        s.auto_block = payload.auto_block
    if payload.webhook_url is not None:
        s.webhook_url = payload.webhook_url.strip()
    return {"success": True}


# ── Attack simulator ───────────────────────────────────────────────────────────
@app.post("/api/sim/start")
def sim_start(email: str = Depends(auth_module.get_current_user)):
    """Launches the headless attack simulator in a subprocess."""
    import subprocess
    root   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = os.path.join(root, "simulate_attacks_headless.py")
    if not os.path.exists(script):
        script = os.path.join(root, "simulate_attacks.py")

    # Auto-start the engine if not already running so it can process the flows
    if not engine_module.engine.running and _loop is not None:
        iface = engine_module.get_best_interface()
        if iface:
            engine_module.start_engine(iface, _loop)

    try:
        subprocess.Popen(
            [sys.executable, script],
            cwd=root,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return {"success": True, "message": "Attack simulation started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Alert log ──────────────────────────────────────────────────────────────────
@app.get("/api/alerts")
def get_alerts(
    limit: int = 200,
    severity: Optional[str] = None,
    email: str = Depends(auth_module.get_current_user),
):
    sev_filter = severity.split(",") if severity else None
    return {"alerts": store.get_alerts(limit=limit, severity_filter=sev_filter)}

@app.get("/api/alerts/export")
def export_alerts(email: str = Depends(auth_module.get_current_user)):
    csv_bytes = store.export_csv()
    fname = f"aips_alerts_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )

@app.get("/api/analytics")
def get_analytics(email: str = Depends(auth_module.get_current_user)):
    return {
        "ts_log":       store.get_ts_log(),
        "conf_history": store.get_conf_history(),
        "throughput":   store.get_throughput(),
        "threat_log":   store.get_threat_log(),
    }


# ── PCAP downloads ─────────────────────────────────────────────────────────────
@app.get("/api/pcap/{filename}")
def download_pcap(filename: str, email: str = Depends(auth_module.get_current_user)):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "pcap_dumps", filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="PCAP file not found")
    if not os.path.abspath(path).startswith(os.path.abspath(os.path.join(root, "pcap_dumps"))):
        raise HTTPException(status_code=403, detail="Forbidden")
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=filename)


# ── WebSocket endpoint ─────────────────────────────────────────────────────────
@app.websocket("/ws/feed")
async def websocket_feed(ws: WebSocket):
    # Token auth for WebSocket
    token = ws.query_params.get("token", "")
    email = auth_module._verify_token(token)
    if not email:
        await ws.close(code=4001)
        return

    await manager.connect(ws)

    # Send current session state on connect
    uptime   = time.time() - store.start_time if store.start_time else 0
    last_bps = store.get_throughput()[-1][1] if store.get_throughput() else 0
    await ws.send_text(json.dumps({
        "type":          "init",
        "running":       engine_module.engine.running,
        "sim_active":    engine_module.engine.sim_active,
        **store.get_stats(uptime, last_bps),
        "recent_alerts": store.get_alerts(limit=20),
    }))

    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        await manager.disconnect(ws)


# ── Serve frontend build (production) ──────────────────────────────────────────
_frontend_dist = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "frontend", "dist"
)
if os.path.exists(_frontend_dist):
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="static")
