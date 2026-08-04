"""
Abstract Base Platform Adapter defining OS-level telemetry primitives.
"""

from typing import Dict, List, Optional, Tuple, Any
import psutil
import subprocess
import re
import os


class BasePlatformAdapter:
    """
    Base class providing generic cross-platform telemetry methods using psutil
    and standard python utilities. Extended by OS-specific adapters.
    """

    def get_platform_name(self) -> str:
        return "Generic"

    def get_default_gateway(self) -> Tuple[Optional[str], Optional[str]]:
        """Returns (gateway_ip, gateway_mac) tuple."""
        # Generic netstat/route parsing or psutil default route
        arp_table = self.get_arp_table()
        # Fallback heuristic: look for gateway IP in netstat / route
        return None, None

    def get_arp_table(self) -> Dict[str, str]:
        """
        Parses system ARP table and returns mapping of IP address -> MAC address.
        """
        arp_table = {}
        try:
            output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                # Match IP and MAC pattern across platforms
                ip_match = re.search(r"\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?", line)
                mac_match = re.search(r"([0-9a-fa-f]{1,2}[:-][0-9a-fa-f]{1,2}[:-][0-9a-fa-f]{1,2}[:-][0-9a-fa-f]{1,2}[:-][0-9a-fa-f]{1,2}[:-][0-9a-fa-f]{1,2})", line, re.IGNORECASE)
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1).lower().replace("-", ":")
                    # Standardize 1-digit hex hex pairs to 2-digit e.g. 0:1:2 -> 00:01:02
                    parts = mac.split(":")
                    mac = ":".join(f"{int(p, 16):02x}" for p in parts if p)
                    arp_table[ip] = mac
        except Exception:
            pass
        return arp_table

    def get_dns_servers(self) -> List[str]:
        """Returns list of configured DNS server IP addresses."""
        dns_servers = []
        try:
            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns_servers.append(parts[1])
        except Exception:
            pass
        return dns_servers

    def get_auth_failures(self, time_window_seconds: int = 60) -> List[Dict[str, Any]]:
        """
        Queries OS security log for authentication failures in the last `time_window_seconds`.
        """
        return []

    def get_persistence_locations(self) -> List[str]:
        """Returns list of system/user auto-start configuration directory paths."""
        return []

    def get_listening_ports(self) -> List[Dict[str, Any]]:
        """Returns list of active listening network ports and responsible processes."""
        ports = []
        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN:
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                    pid = conn.pid
                    process_name = "Unknown"
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                        except Exception:
                            pass
                    ports.append({
                        "port": conn.laddr.port,
                        "ip": conn.laddr.ip,
                        "pid": pid,
                        "process": process_name
                    })
        except Exception:
            pass
        return ports

    def get_usb_devices(self) -> List[Dict[str, str]]:
        """Returns list of connected external USB storage/hardware devices."""
        return []
