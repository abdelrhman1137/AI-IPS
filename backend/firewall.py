import os
import json
import time
import subprocess
import ctypes
from typing import Dict

_DIR = os.path.dirname(os.path.abspath(__file__))
_BLOCKED_FILE = os.path.join(_DIR, "blocked_ips.json")

class FirewallManager:
    def __init__(self):
        self.blocked_ips: Dict[str, dict] = {}
        self._load_state()

    def is_admin(self) -> bool:
        """Check if the current process has Administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _load_state(self):
        if os.path.exists(_BLOCKED_FILE):
            try:
                with open(_BLOCKED_FILE, "r") as f:
                    self.blocked_ips = json.load(f)
            except Exception:
                self.blocked_ips = {}

    def _save_state(self):
        try:
            with open(_BLOCKED_FILE, "w") as f:
                json.dump(self.blocked_ips, f, indent=4)
        except Exception:
            pass

    def block_ip(self, ip: str, reason: str = "") -> bool:
        """Block an IP address via Windows Firewall and save to persistent state."""
        if not self.is_admin():
            return False
            
        rule_name = f"IPS_BLOCK_{ip}"
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                self.blocked_ips[ip] = {
                    "ip": ip,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "reason": reason
                }
                self._save_state()
                return True
            return False
        except Exception:
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address via Windows Firewall and remove from persistent state."""
        if not self.is_admin():
            return False
            
        rule_name = f"IPS_BLOCK_{ip}"
        cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            # Even if netsh fails (e.g. rule doesn't exist), we should remove it from our state
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self._save_state()
            return result.returncode == 0
        except Exception:
            return False

    def get_blocked_list(self) -> list:
        return list(self.blocked_ips.values())

fw_manager = FirewallManager()
