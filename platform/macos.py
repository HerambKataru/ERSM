"""
macOS-specific Platform Adapter for ERSM Host Agent.
"""

from typing import Dict, List, Optional, Tuple, Any
import subprocess
import re
import os
import time
from platform.base_adapter import BasePlatformAdapter


class MacOSAdapter(BasePlatformAdapter):
    """
    macOS adapter utilizing macOS CLI utilities (scutil, route, log, system_profiler).
    """

    def get_platform_name(self) -> str:
        return "macOS"

    def get_default_gateway(self) -> Tuple[Optional[str], Optional[str]]:
        """Determines default gateway IP and MAC address on macOS."""
        gateway_ip = None
        gateway_mac = None

        try:
            # Run route -n get default
            output = subprocess.check_output(["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                if "gateway:" in line:
                    gateway_ip = line.split(":")[-1].strip()
                    break

            if gateway_ip:
                arp_table = self.get_arp_table()
                gateway_mac = arp_table.get(gateway_ip)
        except Exception:
            pass

        return gateway_ip, gateway_mac

    def get_dns_servers(self) -> List[str]:
        """Queries DNS servers via scutil on macOS."""
        dns_servers = []
        try:
            output = subprocess.check_output(["scutil", "--dns"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                if "nameserver[0]" in line or "nameserver[1]" in line:
                    match = re.search(r"nameserver\[\d+\]\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if match:
                        ip = match.group(1)
                        if ip not in dns_servers and not ip.startswith("127."):
                            dns_servers.append(ip)
        except Exception:
            pass

        if not dns_servers:
            dns_servers = super().get_dns_servers()

        return dns_servers

    def get_auth_failures(self, time_window_seconds: int = 60) -> List[Dict[str, Any]]:
        """
        Queries macOS Unified Logging System (`log show`) for authentication failure events.
        Checks for OpenDirectory / LocalAuthentication / opendirectoryd failures.
        """
        failures = []
        try:
            # Query log show for past window
            time_arg = f"{time_window_seconds}s"
            cmd = [
                "log", "show",
                "--predicate", 'eventMessage CONTAINS[c] "failed" OR eventMessage CONTAINS[c] "Authentication failure" OR eventMessage CONTAINS[c] "Failed to authenticate"',
                "--last", time_arg,
                "--style", "syslog"
            ]
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                if "failed" in line.lower() or "authentication" in line.lower():
                    failures.append({
                        "raw": line.strip(),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    })
        except Exception:
            pass
        return failures

    def get_persistence_locations(self) -> List[str]:
        """Returns standard macOS LaunchAgent / LaunchDaemon directory paths."""
        home = os.path.expanduser("~")
        return [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            os.path.join(home, "Library/LaunchAgents"),
            "/etc/pam.d"
        ]

    def get_usb_devices(self) -> List[Dict[str, str]]:
        """Queries connected USB devices on macOS using system_profiler."""
        devices = []
        try:
            output = subprocess.check_output(["system_profiler", "SPUSBDataType", "-xml"], text=True, stderr=subprocess.DEVNULL)
            # Simple fallback text parsing if XML parsing is verbose
            txt_output = subprocess.check_output(["system_profiler", "SPUSBDataType"], text=True, stderr=subprocess.DEVNULL)
            current_dev = None
            for line in txt_output.splitlines():
                line_str = line.strip()
                if line_str and not line_str.startswith("Product ID:") and not line_str.startswith("Vendor ID:") and line.startswith("        ") and not line.startswith("          "):
                    current_dev = line_str.rstrip(":")
                    if current_dev and current_dev not in [d["name"] for d in devices] and "Host Controller" not in current_dev:
                        devices.append({"name": current_dev, "type": "USB Device"})
        except Exception:
            pass
        return devices
