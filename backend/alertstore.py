"""
alertstore.py — In-memory ring-buffer alert store for AI-IDS NIGHTWATCH.
Persists session data in memory; optionally dumps to SQLite on stop.
"""

import time
import csv
import io
from collections import deque
from typing import List, Optional
from dataclasses import dataclass, field, asdict

MAX_ALERTS = 2000
MAX_THROUGHPUT_HISTORY = 500

@dataclass
class AlertEvent:
    """One classified flow event."""
    timestamp:   str
    unix:        float
    label:       str
    severity:    str
    confidence:  float
    port:        int
    duration_us: int
    src:         str   # "LIVE" or "SIM"
    src_ip:      str
    blocked:     bool
    pcap_path:   str
    all_probs:   dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class AlertStore:
    def __init__(self):
        self.reset()

    def reset(self):
        self._alerts:      deque[AlertEvent] = deque(maxlen=MAX_ALERTS)
        self._ts_log:      List[tuple]       = []   # (unix, label, is_sim)
        self._conf_history: List[tuple]      = []   # (label, conf)
        self._throughput:  deque[tuple]      = deque(maxlen=MAX_THROUGHPUT_HISTORY)
        self._threat_log:  List[str]         = []
        self.total_flows:  int = 0
        self.alert_count:  int = 0
        self.start_time:   Optional[float] = None

    def record_flow(self, label: str, conf: float, bps: float):
        """Called for every classified flow (including normal traffic)."""
        self.total_flows += 1
        self._conf_history.append((label, conf))
        if len(self._conf_history) > 1000:
            self._conf_history.pop(0)
        self._throughput.append((time.time(), bps))
        self._threat_log.append(label)
        if len(self._threat_log) > 2000:
            self._threat_log.pop(0)

    def add_alert(self, event: AlertEvent):
        self._alerts.appendleft(event)
        self._ts_log.append((event.unix, event.label, event.src == "SIM"))
        self.alert_count += 1

    # ── Queries ────────────────────────────────────────────────────────────────

    def get_alerts(self, limit: int = 200, severity_filter: Optional[List[str]] = None) -> List[dict]:
        result = list(self._alerts)
        if severity_filter:
            result = [a for a in result if a.severity in severity_filter]
        return [a.to_dict() for a in result[:limit]]

    def get_ts_log(self, since_unix: Optional[float] = None) -> List[tuple]:
        if since_unix is None:
            return list(self._ts_log)
        return [(t, l, s) for t, l, s in self._ts_log if t >= since_unix]

    def get_conf_history(self) -> List[tuple]:
        return list(self._conf_history)

    def get_throughput(self) -> List[tuple]:
        return list(self._throughput)

    def get_threat_log(self) -> List[str]:
        return list(self._threat_log)

    def get_stats(self, uptime_secs: float, last_bps: float) -> dict:
        tf = self.total_flows
        ac = self.alert_count
        import numpy as np
        avg_conf = float(np.mean([c for _, c in self._conf_history])) if self._conf_history else 0.0
        return {
            "total_flows":  tf,
            "alert_count":  ac,
            "threat_rate":  round(ac / tf * 100, 1) if tf > 0 else 0.0,
            "avg_conf":     round(avg_conf, 4),
            "uptime_secs":  round(uptime_secs, 1),
            "throughput_bps": last_bps,
        }

    def export_csv(self) -> bytes:
        """Export full alert log as CSV bytes."""
        if not self._alerts:
            return b""
        out = io.StringIO()
        fields = ["timestamp", "unix", "label", "severity", "confidence",
                  "port", "duration_us", "src", "src_ip", "blocked", "pcap_path"]
        writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for alert in self._alerts:
            writer.writerow(alert.to_dict())
        return out.getvalue().encode()


# Singleton shared across the app
store = AlertStore()
