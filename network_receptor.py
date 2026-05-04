"""
NetworkReceptor  —  Hardened for Windows + Streamlit
=====================================================
Changes vs previous version:
  • flow_timeout reduced to 0.15 s (was 0.5) — much faster flow delivery
  • minimum 1 packet per flow (was 2) — catches all traffic
  • sniffer thread exposes errors via self.sniffer_error
  • raw_packet_count exposed so dashboard can show it
  • File-queue drain uses read+truncate (no Windows rename issue)
  • get_latest_flow() now returns (DataFrame, is_simulated, src_ip)
    – real flows: actual source IP string from the captured packet
    – simulated flows: local machine IP (socket.gethostbyname)
"""

import pandas as pd
import numpy as np
import socket
from scapy.all import sniff, IP, IPv6, TCP, UDP
import time
import os
import json
from threading import Thread, Lock
from queue import Queue, Empty
from collections import deque
from scapy.all import sniff, IP, IPv6, TCP, UDP, wrpcap


def _local_ip() -> str:
    """Best-effort: return the machine's primary LAN IP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return socket.gethostbyname(socket.gethostname())


_LOCAL_IP: str = _local_ip()


class NetworkReceptor:
    INJECT_FILE = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "_inject_queue.jsonl"
    )
    DONE_SIGNAL = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "_inject_done.flag"
    )

    FEATURE_COLUMNS = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Length of Fwd Packets",
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Average Packet Size",
    ]

    def __init__(self):
        self.active_flows    = {}
        self.flow_timeout    = 0.15       # seconds — fast delivery
        self._queue          = Queue()
        self._file_lock      = Lock()
        self._flow_lock      = Lock()
        self.feature_columns = self.FEATURE_COLUMNS
        self.packet_buffer   = deque(maxlen=2500)

        # Diagnostics (dashboard can read these)
        self.raw_packet_count = 0
        self.sniffer_error    = None
        self.sniffer_running  = False
        self._stop_sniff      = False

        # Clean stale inject files from previous session
        for path in (self.INJECT_FILE, self.INJECT_FILE + ".processing",
                     self.DONE_SIGNAL):
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    # ── File-queue drain (read+truncate, no Windows rename needed) ─────────────

    def _drain_file_queue(self):
        if not os.path.exists(self.INJECT_FILE):
            return
        lines = []
        with self._file_lock:
            try:
                with open(self.INJECT_FILE, "r+", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
                    if lines:
                        fh.seek(0)
                        fh.truncate()
            except OSError:
                return

        for line in lines:
            line = line.strip()
            if line:
                try:
                    self._queue.put(json.loads(line))
                except json.JSONDecodeError:
                    pass

    @staticmethod
    def local_ip() -> str:
        """Return the cached local machine IP (used as SIM source label)."""
        return _LOCAL_IP

    # ── Packet callback ────────────────────────────────────────────────────────

    def packet_callback(self, packet):
        self.raw_packet_count += 1
        
        # Buffer raw packet for PCAP export
        self.packet_buffer.append(packet)

        # Determine IP layer
        if packet.haslayer(IP):
            ip_layer = packet[IP]
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]
        else:
            return

        # Determine transport layer
        dport, sport = 0, 0
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            sport = packet[TCP].sport
        elif packet.haslayer(UDP):
            dport = packet[UDP].dport
            sport = packet[UDP].sport

        src = getattr(ip_layer, "src", "0.0.0.0")
        dst = getattr(ip_layer, "dst", "0.0.0.0")
        key = (src, dst, sport, dport)   # src is the real source IP
        pkt_len = len(packet)

        with self._flow_lock:
            if key not in self.active_flows:
                self.active_flows[key] = {
                    "start":  time.time(),
                    "lens":   [pkt_len],
                    "port":   dport,
                    "sport":  sport,
                    "src_ip": src,
                    "dst_ip": dst,
                }
            else:
                self.active_flows[key]["lens"].append(pkt_len)

    # ── Main API ───────────────────────────────────────────────────────────────

    def get_latest_flow(self):
        """
        Returns (DataFrame, is_simulated, src_ip, dst_ip, src_port, dst_port)
        or (None, False, "", "", 0, 0).
        Priority: injected (file or in-process) → real captured.
        """
        # 1. Drain file inject queue
        self._drain_file_queue()

        # 2. Return an in-process injected flow if available
        try:
            row = self._queue.get_nowait()
            return pd.DataFrame([row], columns=self.FEATURE_COLUMNS), True, _LOCAL_IP, "", 0, 0
        except Empty:
            pass

        # 3. Return a matured real-traffic flow
        now = time.time()
        to_process = None

        with self._flow_lock:
            for key, data in self.active_flows.items():
                if now - data["start"] > self.flow_timeout:
                    to_process = (key, data)
                    break

            if to_process:
                del self.active_flows[to_process[0]]

        if to_process:
            key, data = to_process
            duration_s = now - data["start"]
            lens     = data["lens"]
            src_ip   = data.get("src_ip", "0.0.0.0")
            dst_ip   = data.get("dst_ip", "0.0.0.0")
            src_port = int(data.get("sport", 0))
            dst_port = int(data.get("port",  0))

            if len(lens) >= 1:
                safe_s      = max(duration_s, 0.005)
                total_bytes = float(sum(lens))
                total_pkts  = float(len(lens))
                dur_us      = float(min(duration_s * 1e6, 1_000_000))

                row = {
                    "Destination Port":            float(dst_port),
                    "Flow Duration":               dur_us,
                    "Total Fwd Packets":           total_pkts,
                    "Total Length of Fwd Packets": total_bytes,
                    "Fwd Packet Length Max":        float(max(lens)),
                    "Fwd Packet Length Min":        float(min(lens)),
                    "Fwd Packet Length Mean":       float(np.mean(lens)),
                    "Fwd Packet Length Std":        float(np.std(lens)) if len(lens) > 1 else 0.0,
                    "Flow Bytes/s":                float(total_bytes / safe_s),
                    "Flow Packets/s":              float(total_pkts  / safe_s),
                    "Average Packet Size":          float(np.mean(lens)),
                }
                return pd.DataFrame([row], columns=self.FEATURE_COLUMNS), False, src_ip, dst_ip, src_port, dst_port

        return None, False, "", "", 0, 0

    # ── Flush helpers ──────────────────────────────────────────────────────────

    def flush_all(self) -> int:
        """
        Discard ALL buffered injected flows — both from the file queue and
        the in-process Queue.  Returns the number of flows discarded.
        Call this when the simulation DONE_SIGNAL appears so attacks stop
        immediately instead of draining for another minute.
        """
        discarded = 0
        # 1. Truncate the file queue so no more file flows get loaded
        if os.path.exists(self.INJECT_FILE):
            try:
                with self._file_lock:
                    open(self.INJECT_FILE, "w").close()
            except OSError:
                pass
        # 2. Drain and discard the in-process queue
        while True:
            try:
                self._queue.get_nowait()
                discarded += 1
            except Empty:
                break
        return discarded

    # ── Start / Stop sniffer ───────────────────────────────────────────────────

    # Fatal error substrings — these mean the interface is genuinely unusable.
    _FATAL_ERRORS = ("not found", "no such device", "permission denied", "access denied")

    def start_sniffing(self, interface: str):
        """Start continuous packet capture. Resets per-session counters first."""
        self.sniffer_error   = None
        self.sniffer_running = False
        self._stop_sniff     = False

        # Reset per-session counters FIRST (raw_packet_count before flows/buffer)
        # so the packet callback cannot race and increment before zero is written.
        self.raw_packet_count = 0
        with self._flow_lock:
            self.active_flows.clear()
        self.packet_buffer.clear()

        def _worker():
            # Mark running immediately so the dashboard status dot goes green.
            self.sniffer_running = True
            consecutive_errors = 0
            try:
                while not self._stop_sniff:
                    try:
                        sniff(
                            iface=interface,
                            prn=self.packet_callback,
                            store=0,
                            stop_filter=lambda p: self._stop_sniff,
                            timeout=1.0,
                        )
                        # Successful sniff() window — reset error streak.
                        consecutive_errors = 0
                        self.sniffer_error = None
                    except Exception as exc:
                        err_msg = str(exc)
                        self.sniffer_error = err_msg
                        consecutive_errors += 1

                        # Fatal errors: wrong interface name, no permission, etc.
                        # Stop immediately — retrying won't help.
                        if any(s in err_msg.lower() for s in self._FATAL_ERRORS):
                            break

                        # Transient errors: retry up to 5 times with backoff.
                        if consecutive_errors >= 5:
                            break

                        # Back off: 0.5s, 1s, 1.5s, 2s …
                        backoff = min(consecutive_errors * 0.5, 2.0)
                        time.sleep(backoff)
            finally:
                self.sniffer_running = False

        Thread(target=_worker, daemon=True).start()

    def stop_sniffing(self):
        """Halts the scapy capture thread."""
        self._stop_sniff = True

    # ── Packet Export ──────────────────────────────────────────────────────────

    def dump_pcap(self, target_ip: str, filename: str) -> str:
        """
        Extracts packets related to the target_ip from the ring buffer
        and writes them to a pcap file using scapy wrpcap.
        Returns the absolute filepath.
        """
        # Ensure the directory exists
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        
        matching_packets = []
        for packet in list(self.packet_buffer):
            src, dst = "", ""
            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst
            elif packet.haslayer(IPv6):
                src = packet[IPv6].src
                dst = packet[IPv6].dst
            
            if src == target_ip or dst == target_ip:
                matching_packets.append(packet)
                
        if matching_packets:
            wrpcap(filename, matching_packets)
            
        return os.path.abspath(filename)