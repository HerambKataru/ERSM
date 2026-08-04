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
        detailed = self.get_usb_devices_detailed()
        return [{"name": d.get("name", "USB Device"), "type": "USB Device"} for d in detailed]

    def get_usb_devices_detailed(self) -> List[Dict[str, Any]]:
        """
        Returns list of USB devices with vendor, product_id, serial, and storage indicator.
        Format: [{'name': str, 'vendor': str, 'product_id': str, 'serial': str, 'is_storage': bool}]
        """
        return []

    def get_firewall_status(self) -> Dict[str, Any]:
        """
        Queries host firewall status.
        Format: {'enabled': bool, 'config_changed': bool, 'blocked_events': List[Dict[str, Any]]}
        """
        return {"enabled": True, "config_changed": False, "blocked_events": []}

    def get_network_connections_detailed(self) -> Dict[str, Any]:
        """
        Returns stats on active network connections (inbound vs outbound count, remote targets).
        """
        inbound = 0
        outbound = 0
        connections_list = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status in [psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT] and conn.raddr:
                    # Heuristic: local port < 1024 or listening service is inbound
                    is_inbound = conn.laddr and conn.laddr.port in [80, 443, 22, 21, 25, 8080]
                    if is_inbound:
                        inbound += 1
                    else:
                        outbound += 1
                    connections_list.append({
                        "local_ip": conn.laddr.ip if conn.laddr else "",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "status": conn.status,
                        "pid": conn.pid
                    })
        except Exception:
            pass
        return {
            "inbound_count": inbound,
            "outbound_count": outbound,
            "total_count": len(connections_list),
            "connections": connections_list
        }

    def get_external_security_logs(self) -> List[Dict[str, Any]]:
        """
        Queries platform native AV/Security logs (Windows Defender, macOS unified log, auditd).
        """
        return []

