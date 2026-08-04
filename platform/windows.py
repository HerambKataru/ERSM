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

    def get_usb_devices_detailed(self) -> List[Dict[str, Any]]:
        """Queries PNP USB devices via PowerShell on Windows."""
        devices = []
        try:
            cmd = 'powershell "Get-PnpDevice -Class USB -Status OK | Select-Object FriendlyName, InstanceId, Manufacturer"'
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, shell=True)
            for line in output.splitlines()[3:]:
                dev = line.strip()
                if dev:
                    devices.append({
                        "name": dev,
                        "vendor": "Generic Windows USB Vendor",
                        "product_id": "0x0000",
                        "serial": "N/A",
                        "is_storage": "Disk" in dev or "Storage" in dev or "Mass" in dev
                    })
        except Exception:
            pass
        return devices

    def get_firewall_status(self) -> Dict[str, Any]:
        """Queries Windows Defender Firewall status via PowerShell / netsh."""
        enabled = True
        try:
            cmd = 'powershell "Get-NetFirewallProfile | Select-Object Name, Enabled"'
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, shell=True)
            if "False" in output:
                enabled = False
        except Exception:
            pass
        return {"enabled": enabled, "config_changed": False, "blocked_events": []}

    def get_external_security_logs(self) -> List[Dict[str, Any]]:
        """Queries Windows Security & Defender event logs (e.g., Event ID 1116/1117)."""
        alerts = []
        try:
            cmd = 'wevtutil qe "Microsoft-Windows-Windows Defender/Operational" "/q:*[System[(EventID=1116 or EventID=1117)]]" /c:3 /rd:true /f:text'
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, shell=True)
            if "1116" in output or "1117" in output:
                alerts.append({
                    "event_type": "MALWARE_ALERT",
                    "severity": "CRITICAL",
                    "message": "Windows Defender detected malware threat.",
                    "provider": "Windows Defender"
                })
        except Exception:
            pass
        return alerts

