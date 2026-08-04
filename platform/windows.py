"""
Windows-specific Platform Adapter for ERSM Host Agent.
"""

from typing import Dict, List, Optional, Tuple, Any
import subprocess
import re
import os
import time
from platform.base_adapter import BasePlatformAdapter


class WindowsAdapter(BasePlatformAdapter):
    """
    Windows platform adapter supporting Windows Event Log, Registry Persistence, and PowerShell/WMI queries.
    """

    def get_platform_name(self) -> str:
        return "Windows"

    def get_default_gateway(self) -> Tuple[Optional[str], Optional[str]]:
        """Parses ipconfig / route print for default gateway on Windows."""
        gateway_ip = None
        gateway_mac = None

        try:
            output = subprocess.check_output("ipconfig", text=True, stderr=subprocess.DEVNULL, shell=True)
            for line in output.splitlines():
                if "Default Gateway" in line:
                    match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if match:
                        gateway_ip = match.group(1)
                        break

            if gateway_ip:
                arp_table = self.get_arp_table()
                gateway_mac = arp_table.get(gateway_ip)
        except Exception:
            pass

        return gateway_ip, gateway_mac

    def get_dns_servers(self) -> List[str]:
        """Queries DNS servers via ipconfig /all or PowerShell on Windows."""
        dns_servers = []
        try:
            output = subprocess.check_output("ipconfig /all", text=True, stderr=subprocess.DEVNULL, shell=True)
            in_dns_section = False
            for line in output.splitlines():
                if "DNS Servers" in line:
                    in_dns_section = True
                    match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if match:
                        dns_servers.append(match.group(1))
                elif in_dns_section and line.strip() and not ":" in line:
                    match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if match:
                        dns_servers.append(match.group(1))
                elif in_dns_section and ":" in line:
                    in_dns_section = False
        except Exception:
            pass
        return dns_servers

    def get_auth_failures(self, time_window_seconds: int = 60) -> List[Dict[str, Any]]:
        """
        Queries Windows Security Event Log for Event ID 4625 (An account failed to log on).
        Uses wevtutil command tool.
        """
        failures = []
        try:
            # Query Security Log via wevtutil
            cmd = 'wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:5 /rd:true /f:text'
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, shell=True)
            if "Event ID: 4625" in output or "4625" in output:
                failures.append({
                    "raw": "Windows Event 4625: Logon Failure",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                })
        except Exception:
            pass
        return failures

    def get_persistence_locations(self) -> List[str]:
        """Returns standard Windows startup folders and registry run locations."""
        appdata = os.getenv("APPDATA", r"C:\Users\Public")
        programdata = os.getenv("PROGRAMDATA", r"C:\ProgramData")

        return [
            os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\Startup"),
            r"C:\Windows\System32\Tasks"
        ]

    def get_usb_devices(self) -> List[Dict[str, str]]:
        """Queries PNP USB devices via PowerShell on Windows."""
        devices = []
        try:
            cmd = 'powershell "Get-PnpDevice -Class USB -Status OK | Select-Object -Property FriendlyName"'
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, shell=True)
            for line in output.splitlines()[3:]:
                dev = line.strip()
                if dev:
                    devices.append({"name": dev, "type": "USB Device"})
        except Exception:
            pass
        return devices
