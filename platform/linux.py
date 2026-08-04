"""
Linux-specific Platform Adapter for ERSM Host Agent.
"""

from typing import Dict, List, Optional, Tuple, Any
import subprocess
import re
import os
import time
from platform.base_adapter import BasePlatformAdapter


class LinuxAdapter(BasePlatformAdapter):
    """
    Linux platform adapter utilizing /proc filesystem, ip route, journalctl, and systemd.
    """

    def get_platform_name(self) -> str:
        return "Linux"

    def get_default_gateway(self) -> Tuple[Optional[str], Optional[str]]:
        """Parses ip route / /proc/net/route for default gateway on Linux."""
        gateway_ip = None
        gateway_mac = None

        try:
            output = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
            parts = output.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    gateway_ip = parts[idx + 1]

            if gateway_ip:
                arp_table = self.get_arp_table()
                gateway_mac = arp_table.get(gateway_ip)
        except Exception:
            pass

        return gateway_ip, gateway_mac

    def get_arp_table(self) -> Dict[str, str]:
        """Reads /proc/net/arp on Linux for high-speed local ARP resolution."""
        arp_table = {}
        try:
            if os.path.exists("/proc/net/arp"):
                with open("/proc/net/arp", "r") as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[0]
                            mac = parts[3].lower()
                            if mac != "00:00:00:00:00:00":
                                arp_table[ip] = mac
        except Exception:
            pass

        if not arp_table:
            arp_table = super().get_arp_table()

        return arp_table

    def get_auth_failures(self, time_window_seconds: int = 60) -> List[Dict[str, Any]]:
        """
        Queries /var/log/auth.log, /var/log/secure, or journalctl for failed auth attempts on Linux.
        """
        failures = []
        try:
            # Try journalctl first
            cmd = ["journalctl", "_COMM=sshd", "-n", "20", "--no-pager"]
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                if "Failed password" in line or "authentication failure" in line:
                    failures.append({
                        "raw": line.strip(),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    })
        except Exception:
            # Fallback to reading /var/log/auth.log
            auth_paths = ["/var/log/auth.log", "/var/log/secure"]
            for path in auth_paths:
                if os.path.exists(path) and os.access(path, os.R_OK):
                    try:
                        with open(path, "r") as f:
                            lines = f.readlines()[-50:]
                            for line in lines:
                                if "Failed password" in line or "authentication failure" in line:
                                    failures.append({
                                        "raw": line.strip(),
                                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                                    })
                    except Exception:
                        pass
        return failures

    def get_persistence_locations(self) -> List[str]:
        """Returns Linux systemd, cron, and autostart directory paths."""
        home = os.path.expanduser("~")
        return [
            "/etc/systemd/system",
            "/etc/init.d",
            "/etc/cron.d",
            "/etc/crontab",
            os.path.join(home, ".config/autostart"),
            "/etc/xdg/autostart"
        ]

    def get_usb_devices(self) -> List[Dict[str, str]]:
        """Queries connected USB devices on Linux via lsusb or /sys/bus/usb/devices."""
        devices = []
        try:
            output = subprocess.check_output(["lsusb"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                if "ID" in line:
                    parts = line.split("ID")
                    if len(parts) > 1:
                        devices.append({"name": parts[1].strip(), "type": "USB Device"})
        except Exception:
            pass
        return devices
