"""
Network Security Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors active sockets, port scans, connection floods, and listening ports.
"""

import time
from typing import Dict, Any, Set, Tuple, List
import psutil
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class NetworkMonitor(BaseMonitor):
    """
    Passive network telemetry monitor detecting port scanning, connection bursts, and listening port changes.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("NetworkMonitor", event_bus, platform_adapter, config)
        self.port_scan_threshold = self.config.get("port_scan_threshold_ports", 20)
        self.port_scan_window = self.config.get("port_scan_window_seconds", 10)
        self.flood_threshold = self.config.get("connection_flood_threshold", 500)

        self._known_listening_ports: Set[int] = set()
        self._initialized_ports = False
        self._connection_history: List[Tuple[float, str, int]] = []  # (ts, raddr, rport)
        self._last_scan_alert_time = 0.0
        self._last_flood_alert_time = 0.0

    def _check(self) -> None:
        now = time.time()

        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return

        current_listening: Set[int] = set()
        new_active_connections: List[Tuple[str, int]] = []

        for conn in connections:
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                current_listening.add(conn.laddr.port)
            elif conn.status in [psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT] and conn.raddr:
                new_active_connections.append((conn.raddr.ip, conn.raddr.port))
                self._connection_history.append((now, conn.raddr.ip, conn.raddr.port))

        # 1. Listening Port Monitoring
        if not self._initialized_ports:
            self._known_listening_ports = current_listening
            self._initialized_ports = True
        else:
            new_ports = current_listening - self._known_listening_ports
            for port in new_ports:
                event = SecurityEvent(
                    category=EventCategory.NETWORK.value,
                    event="NEW_LISTENING_PORT",
                    severity=EventSeverity.MEDIUM.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=15,
                    message=f"New listening port opened on local machine: Port {port}",
                    metadata={"port": port}
                )
                self.publish_event(event)
            self._known_listening_ports = current_listening

        # Clean old connection history
        cutoff = now - self.port_scan_window
        self._connection_history = [
            (ts, ip, port) for ts, ip, port in self._connection_history
            if ts >= cutoff
        ]

        # 2. Port Scan Detection
        # Count unique ports targeted by remote IP or touched locally
        remote_ip_ports: Dict[str, Set[int]] = {}
        for ts, ip, port in self._connection_history:
            if ip not in remote_ip_ports:
                remote_ip_ports[ip] = set()
            remote_ip_ports[ip].add(port)

        for remote_ip, ports in remote_ip_ports.items():
            if len(ports) >= self.port_scan_threshold:
                if (now - self._last_scan_alert_time) >= self.port_scan_window:
                    event = SecurityEvent(
                        category=EventCategory.NETWORK.value,
                        event="PORT_SCAN_SUSPECTED",
                        severity=EventSeverity.HIGH.value,
                        confidence=EventConfidence.HIGH.value,
                        risk=30,
                        message=f"Port scan pattern detected from {remote_ip}: attempted {len(ports)} unique ports within {self.port_scan_window}s.",
                        metadata={"source_ip": remote_ip, "port_count": len(ports), "ports": list(ports)[:10]}
                    )
                    self.publish_event(event)
                    self._last_scan_alert_time = now

        # 3. Connection Flood Detection
        recent_connection_count = len(self._connection_history)
        if recent_connection_count >= self.flood_threshold:
            if (now - self._last_flood_alert_time) >= self.port_scan_window:
                event = SecurityEvent(
                    category=EventCategory.NETWORK.value,
                    event="CONNECTION_FLOOD_ANOMALY",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.MEDIUM.value,
                    risk=30,
                    message=f"High connection burst detected: {recent_connection_count} active network connections in window.",
                    metadata={"connection_count": recent_connection_count, "threshold": self.flood_threshold}
                )
                self.publish_event(event)
                self._last_flood_alert_time = now
