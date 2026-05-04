"""
ids_engine.py — IDS inference engine wrapper for the AIPS FastAPI backend.

Runs NetworkReceptor + ML model in a background thread, pushes events to
connected WebSocket clients and the AlertStore.
"""

import os
import sys
import time
import json
import random
import asyncio
import ipaddress
import subprocess
import threading
import numpy as np
import joblib
from typing import Callable, Optional, Set

# Add the project root to sys.path so we can import network_receptor
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from network_receptor import NetworkReceptor
from alertstore import store, AlertEvent

# ── Constants ──────────────────────────────────────────────────────────────────
FEAT_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Average Packet Size",
]
VER_ATTACKS = os.path.join(_ROOT, "verified_attacks.json")
DONE_SIGNAL = os.path.join(_ROOT, "_inject_done.flag")

HIGH_RISK = {"DoS", "DDoS", "Brute Force", "Botnet"}

# ── Model loading ──────────────────────────────────────────────────────────────
_model_path  = os.path.join(_ROOT, "trained_ids_model.pkl")
_scaler_path = os.path.join(_ROOT, "scaler.pkl")
_label_path  = os.path.join(_ROOT, "label_map.pkl")

model     = joblib.load(_model_path)
scaler    = joblib.load(_scaler_path)
label_map = joblib.load(_label_path)       # int → str
label_inv = {v: k for k, v in label_map.items()}

receptor = NetworkReceptor()


# ── Helpers ────────────────────────────────────────────────────────────────────
def get_severity(label: str, conf: float) -> str:
    if label == "Normal Traffic":
        return "CLEAN"
    if conf >= 0.95 and label in HIGH_RISK:
        return "CRITICAL"
    if conf >= 0.85:
        return "HIGH"
    return "MEDIUM"

def predict_flow(flow_values: list, conf_threshold: float):
    scaled = scaler.transform([flow_values])
    probs  = model.predict_proba(scaled)[0]
    idx    = int(np.argmax(probs))
    conf   = float(probs[idx])
    label  = label_map.get(idx, "Unknown")
    all_p  = {label_map[i]: float(p) for i, p in enumerate(probs)}
    if conf < conf_threshold:
        label = "Normal Traffic"
        conf  = all_p.get("Normal Traffic", conf)
    return label, conf, all_p


# ── Engine settings (mutable at runtime) ─────────────────────────────────────
class EngineSettings:
    def __init__(self):
        self.conf_threshold: float = 0.80
        self.guard:          int   = 1
        self.auto_block:     bool  = False
        self.webhook_url:    str   = ""
        self.interface:      str   = ""

settings = EngineSettings()


# ── Engine state ───────────────────────────────────────────────────────────────
class EngineState:
    def __init__(self):
        self.running:      bool  = False
        self.sim_active:   bool  = False
        self.sniffer_ok:   bool  = False
        self._consec:      dict  = {}
        self._thread:      Optional[threading.Thread] = None
        self._stop_evt:    threading.Event = threading.Event()
        # Broadcast callback set from main.py
        self.broadcast: Optional[Callable] = None

engine = EngineState()

# The running asyncio event loop — set at startup by main.py
_event_loop: Optional[asyncio.AbstractEventLoop] = None

# Cached best interface — probed once at startup, reused on every Start press
_cached_interface: str = ""

def set_loop(loop: asyncio.AbstractEventLoop):
    global _event_loop
    _event_loop = loop


# ── IP classification helper ──────────────────────────────────────────────────
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
]

def is_private_ip(ip: str) -> bool:
    """Return True if the IP is a private/local range that should never be blocked."""
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True  # unparseable — skip to be safe


from firewall import fw_manager

def unblock_ip(ip: str) -> bool:
    """Unblock an IP address via Windows Firewall. Returns True on success."""
    return fw_manager.unblock_ip(ip)


BLOCK_CONF_THRESHOLD = 0.80   # minimum confidence to trigger a block (Updated to 0.80 as per user requirement)

# ── Mitigation ─────────────────────────────────────────────────────────────────
def execute_mitigation(ip: str, severity: str, label: str, conf: float, is_sim: bool):
    blocked   = False
    pcap_path = ""

    # Dump PCAP for any HIGH or CRITICAL alert
    if severity in ("CRITICAL", "HIGH") and ip:
        os.makedirs(os.path.join(_ROOT, "pcap_dumps"), exist_ok=True)
        fname = os.path.join(_ROOT, "pcap_dumps",
                             f"threat_{int(time.time())}_{ip.replace('.','_')}.pcap")
        try:
            pcap_path = receptor.dump_pcap(ip, fname)
        except Exception:
            pass

    # Block if: auto_block enabled, severity is HIGH or CRITICAL, conf above threshold,
    #           IP is not private/local, and not already blocked.
    should_block = (
        settings.auto_block
        and severity in ("CRITICAL", "HIGH")
        and conf >= BLOCK_CONF_THRESHOLD
        and ip
        and not is_private_ip(ip)
        and ip not in fw_manager.blocked_ips
        and not is_sim   # never block during simulation — flows use fake IPs
    )

    if should_block:
        reason = f"{severity} {label} ({conf:.1%} conf)"
        blocked = fw_manager.block_ip(ip, reason)

    # Webhook notification for HIGH / CRITICAL
    if severity in ("CRITICAL", "HIGH") and settings.webhook_url:
        import requests as req_lib
        payload = {
            "content": (
                f"🚨 **{severity} ALERT**: {label} detected — {conf:.1%} confidence\n"
                f"**Source IP**: `{ip}`\n"
                f"**Action**: {'Blocked (IPS_BLOCK_{ip})' if blocked else 'Logged'}\n"
                f"**Mode**: {'Simulation' if is_sim else 'Live'}"
            )
        }
        try:
            req_lib.post(settings.webhook_url, json=payload, timeout=0.5)
        except Exception:
            pass

    return blocked, pcap_path


# ── Monitoring loop (background thread) ───────────────────────────────────────
def _monitoring_loop(loop: asyncio.AbstractEventLoop):
    """Runs in a daemon thread; pushes events to the asyncio event loop."""
    last_metric_ts = 0.0
    last_normal_ts = 0.0

    while not engine._stop_evt.is_set():
        # Check for simulation done signal
        if os.path.exists(DONE_SIGNAL):
            engine.sim_active = False
            receptor.flush_all()
            try:
                os.remove(DONE_SIGNAL)
            except OSError:
                pass
            _broadcast_event(loop, {"type": "sim_done"})

        try:
            live_flow, is_sim, src_ip, dst_ip, src_port, dst_port = receptor.get_latest_flow()
        except Exception as e:
            _broadcast_event(loop, {"type": "error", "message": str(e)})
            time.sleep(0.1)
            continue

        if is_sim and not engine.sim_active:
            engine.sim_active = True
            _broadcast_event(loop, {"type": "sim_start"})

        now_unix = time.time()

        # --- Emit periodic metric heartbeats (max 2 times per sec) ---
        if now_unix - last_metric_ts >= 0.5:
            last_metric_ts = now_unix
            # Keep engine.sniffer_ok in sync with live thread state
            engine.sniffer_ok = receptor.sniffer_running
            uptime = now_unix - store.start_time if store.start_time else 0
            last_bps = store.get_throughput()[-1][1] if store.get_throughput() else 0
            _broadcast_event(loop, {
                "type": "metric",
                "raw_packets":    receptor.raw_packet_count,
                "total_flows":    store.total_flows,
                "alert_count":    store.alert_count,
                "throughput_bps": last_bps,
                "uptime_secs":    round(uptime, 1),
                "sniffer_running": receptor.sniffer_running,
                "sniffer_error":  receptor.sniffer_error or "",
            })

        if live_flow is None:
            time.sleep(0.01)   # Yield slightly if no active flows
            continue

        # --- Process flow ---
        bps  = float(live_flow["Flow Bytes/s"].iloc[0])
        port = float(live_flow["Destination Port"].iloc[0])
        dur  = float(live_flow["Flow Duration"].iloc[0])

        try:
            label, conf, all_p = predict_flow(
                live_flow.values.flatten().tolist(),
                settings.conf_threshold,
            )
        except Exception as e:
            _broadcast_event(loop, {"type": "error", "message": f"Model error: {e}"})
            time.sleep(0.1)
            continue

        store.record_flow(label, conf, bps)

        # Consecutive guard
        if label != "Normal Traffic":
            engine._consec[label] = engine._consec.get(label, 0) + 1
        else:
            for k in list(engine._consec):
                engine._consec[k] = max(0, engine._consec[k] - 1)

        fire_alert = (
            label != "Normal Traffic"
            and engine._consec.get(label, 0) >= settings.guard
        )
        severity = get_severity(label, conf) if fire_alert else "CLEAN"
        disp_lbl = label if fire_alert else "Normal Traffic"

        # Emit flow event to all WebSocket clients
        flow_msg = {
            "type":        "flow",
            "timestamp":   time.strftime("%H:%M:%S"),
            "unix":        now_unix,
            "label":       disp_lbl,
            "severity":    severity,
            "confidence":  round(conf, 4),
            "port":        int(port),
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "src_port":    src_port,
            "dst_port":    dst_port,
            "is_sim":      is_sim and fire_alert,
            "all_probs":   {k: round(v, 4) for k, v in all_p.items()},
            "fired":       fire_alert,
            "duration_us": int(dur),
        }

        if fire_alert:
            blocked, pcap_path = execute_mitigation(src_ip, severity, label, conf, is_sim)
            flow_msg["blocked"]   = blocked
            flow_msg["pcap_path"] = pcap_path

            alert = AlertEvent(
                timestamp=time.strftime("%H:%M:%S"),
                unix=now_unix,
                label=label,
                severity=severity,
                confidence=round(conf, 4),
                port=int(port),
                duration_us=int(dur),
                src="SIM" if is_sim else "LIVE",
                src_ip=src_ip,
                blocked=blocked,
                pcap_path=pcap_path,
                all_probs=flow_msg["all_probs"],
            )
            store.add_alert(alert)
            # Always broadcast alerts immediately
            _broadcast_event(loop, flow_msg)
        else:
            flow_msg["blocked"]   = False
            flow_msg["pcap_path"] = ""
            # Throttle broadcast of normal flows to the UI to max ~4 per second to prevent React stuttering
            if now_unix - last_normal_ts >= 0.25:
                last_normal_ts = now_unix
                _broadcast_event(loop, flow_msg)


def _broadcast_event(loop: Optional[asyncio.AbstractEventLoop], msg: dict):
    target = loop or _event_loop
    if engine.broadcast and target:
        asyncio.run_coroutine_threadsafe(engine.broadcast(msg), target)


# ── Public API ─────────────────────────────────────────────────────────────────
def start_engine(interface: str, loop: Optional[asyncio.AbstractEventLoop] = None):
    if engine.running:
        return
    # Use the stored loop if none passed
    target_loop = loop or _event_loop
    settings.interface = interface
    engine.running     = True
    engine._stop_evt.clear()
    engine._consec.clear()
    store.start_time   = time.time()

    # Start sniffer — sniffer_ok is driven by receptor.sniffer_running
    # (updated inside the capture thread) not by whether this call throws.
    # Note: start_sniffing() resets raw_packet_count to 0 internally.
    receptor.start_sniffing(interface=interface)
    # Give the Npcap thread ~250 ms to either bind the interface or report an error
    # before the monitoring loop reads sniffer_running for the first heartbeat.
    time.sleep(0.25)
    engine.sniffer_ok = receptor.sniffer_running

    # Broadcast an immediate "session started" metric so the frontend counter
    # resets to 0 right away (instead of waiting up to 0.5s for the first heartbeat).
    _broadcast_event(target_loop, {
        "type":            "metric",
        "raw_packets":     receptor.raw_packet_count,   # 0 after reset
        "total_flows":     store.total_flows,
        "alert_count":     store.alert_count,
        "throughput_bps":  0,
        "uptime_secs":     0.0,
        "sniffer_running": receptor.sniffer_running,
        "sniffer_error":   receptor.sniffer_error or "",
    })

    engine._thread = threading.Thread(
        target=_monitoring_loop,
        args=(target_loop,),
        daemon=True,
    )
    engine._thread.start()


def stop_engine():
    engine.running = False
    engine._stop_evt.set()
    receptor.stop_sniffing()
    receptor.flush_all()


def clear_session():
    stop_engine()
    store.reset()
    engine._consec.clear()
    engine.sim_active = False
    engine.sniffer_ok = False


def run_self_test(loop: asyncio.AbstractEventLoop):
    """Run 12 verified attacks synchronously, broadcasting results."""
    if not os.path.exists(VER_ATTACKS):
        return 0, "verified_attacks.json not found — run build_attack_cache.py"

    with open(VER_ATTACKS) as f:
        data = json.load(f)

    sample = random.sample(data, min(12, len(data)))
    fired  = 0
    now    = time.time()
    store.start_time = store.start_time or now

    for row in sample:
        vals  = [row[k] for k in FEAT_COLS]
        label, conf, all_p = predict_flow(vals, settings.conf_threshold)
        bps   = float(row.get("Flow Bytes/s", 0))
        store.record_flow(label, conf, bps)

        if label != "Normal Traffic":
            engine._consec[label] = engine._consec.get(label, 0) + 1

        if label != "Normal Traffic" and engine._consec.get(label, 0) >= settings.guard:
            sev     = get_severity(label, conf)
            src_ip  = row.get("Source IP", "127.0.0.1")
            blocked, pcap_path = execute_mitigation(src_ip, sev, label, conf, is_sim=True)
            fired  += 1

            alert = AlertEvent(
                timestamp=time.strftime("%H:%M:%S"),
                unix=now,
                label=label,
                severity=sev,
                confidence=round(conf, 4),
                port=int(row.get("Destination Port", 0)),
                duration_us=int(row.get("Flow Duration", 0)),
                src="SIM",
                src_ip=row.get("Source IP", "127.0.0.1"),
                blocked=blocked,
                pcap_path=pcap_path,
                all_probs={k: round(v, 4) for k, v in all_p.items()},
            )
            store.add_alert(alert)

            _broadcast_event(loop, {
                "type":       "flow",
                "timestamp":  alert.timestamp,
                "unix":       now,
                "label":      label,
                "severity":   sev,
                "confidence": alert.confidence,
                "port":       alert.port,
                "src_ip":     src_ip,
                "dst_ip":     "",
                "src_port":   0,
                "dst_port":   alert.port,
                "is_sim":     True,
                "blocked":    blocked,
                "pcap_path":  pcap_path,
                "all_probs":  alert.all_probs,
                "fired":      True,
            })

    msg = (f"Self-Test — {fired}/{len(sample)} attacks detected"
           if fired > 0
           else "Self-Test: 0 alerts — try lowering the Confidence Threshold")
    return fired, msg


def get_interfaces() -> list:
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception:
        return []


def get_best_interface() -> str:
    """
    Probe every available interface by actually opening it with Scapy.
    Returns the first interface that has live traffic (pkts > 0 in 0.15s window).
    Only caches when a live-traffic NIC is found — never caches zero-traffic or
    loopback interfaces, because the pre-warm could run before traffic exists.
    Falls back to first openable non-loopback, then loopback, if no live traffic.
    """
    global _cached_interface
    if _cached_interface:
        return _cached_interface

    try:
        from scapy.all import get_if_list, sniff as scapy_sniff
    except Exception:
        return ""

    ifaces = get_if_list()
    openable_non_loopback: list = []
    openable_loopback:     list = []

    for iface in ifaces:
        try:
            pkts = scapy_sniff(iface=iface, count=5, timeout=0.15, store=1)
            if len(pkts) > 0:
                # Found a live interface — cache and return immediately.
                # Only cache live-traffic interfaces; never cache loopback/idle.
                _cached_interface = iface
                return iface
            is_lb = "loopback" in iface.lower() or iface.endswith("Loopback")
            (openable_loopback if is_lb else openable_non_loopback).append(iface)
        except Exception:
            pass   # interface cannot be opened by this process — skip

    # No live traffic found — return best fallback WITHOUT caching,
    # so the next Start press re-probes (traffic may have started by then).
    if openable_non_loopback:
        return openable_non_loopback[0]
    if openable_loopback:
        return openable_loopback[0]
    return ifaces[0] if ifaces else ""
