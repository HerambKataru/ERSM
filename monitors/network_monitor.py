"""
Network Security & Connection Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors active socket states, listening ports, inbound/outbound connection bursts, and port scans.
"""

import time
from typing import Dict, Any, Set, Tuple, List
import psutil
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class NetworkMonitor(BaseMonitor):
    """
    Monitors listening ports, port removal, connection spikes, inbound/outbound anomalies, and port scans.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("NetworkMonitor", event_bus, platform_adapter, config)
        self.port_scan_threshold = self.config.get("port_scan_threshold_ports", 20)
        self.port_scan_window = self.config.get("port_scan_window_seconds", 10)
        self.flood_threshold = self.config.get("connection_flood_threshold", 500)
        self.outbound_threshold = self.config.get("outbound_threshold", 100)
        self.inbound_threshold = self.config.get("inbound_threshold", 50)
        self.spike_threshold = self.config.get("spike_threshold", 80)
        self.unexpected_ports = set(self.config.get("unexpected_ports", [4444, 31337, 6667]))

        self._known_listening_ports: Set[int] = set()
        self._initialized_ports = False
        self._connection_history: List[Tuple[float, str, int]] = []  # (ts, raddr, rport)
        self._last_scan_alert_time = 0.0
        self._last_flood_alert_time = 0.0
        self._last_outbound_alert_time = 0.0
        self._last_inbound_alert_time = 0.0
        self._last_spike_alert_time = 0.0

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

        # 1. Listening Port Monitoring (New & Removed Ports)
        if not self._initialized_ports:
            self._known_listening_ports = current_listening
            self._initialized_ports = True
        else:
            # New Listening Ports
            new_ports = current_listening - self._known_listening_ports
            for port in new_ports:
                sev = EventSeverity.HIGH.value if port in self.unexpected_ports else EventSeverity.MEDIUM.value
                event = SecurityEvent(
                    category=EventCategory.PORT.value,
                    event="NEW_LISTENING_PORT",
                    severity=sev,
                    confidence=EventConfidence.HIGH.value,
                    risk=30 if port in self.unexpected_ports else 15,
                    module=self.name,
                    message=f"New listening port opened on local host: Port {port} {'(UNEXPECTED SERVICE)' if port in self.unexpected_ports else ''}",
                    metadata={"port": port, "unexpected": port in self.unexpected_ports}
                )
                self.publish_event(event)

            # Removed Listening Ports
            removed_ports = self._known_listening_ports - current_listening
            for port in removed_ports:
                event = SecurityEvent(
                    category=EventCategory.PORT.value,
                    event="LISTENING_PORT_REMOVED",
                    severity=EventSeverity.INFO.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=0,
                    module=self.name,
                    message=f"Listening port closed/removed on local host: Port {port}",
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

        # 2. Connection Volume & Anomalies (Inbound vs Outbound Stats)
        conn_stats = self.platform_adapter.get_network_connections_detailed()
        inbound_cnt = conn_stats.get("inbound_count", 0)
        outbound_cnt = conn_stats.get("outbound_count", 0)
        total_cnt = conn_stats.get("total_count", 0)

        # Outbound Anomaly
        if outbound_cnt >= self.outbound_threshold:
            if (now - self._last_outbound_alert_time) >= self.port_scan_window:
                event = SecurityEvent(
                    category=EventCategory.NETWORK.value,
                    event="OUTBOUND_CONNECTION_ANOMALY",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.MEDIUM.value,
                    risk=30,
                    module=self.name,
                    message=f"High outbound connection anomaly: {outbound_cnt} active outbound connections.",
                    metadata={"outbound_count": outbound_cnt, "threshold": self.outbound_threshold}
                )
                self.publish_event(event)
                self._last_outbound_alert_time = now

        # Inbound Anomaly
        if inbound_cnt >= self.inbound_threshold:
            if (now - self._last_inbound_alert_time) >= self.port_scan_window:
                event = SecurityEvent(
                    category=EventCategory.NETWORK.value,
                    event="INBOUND_CONNECTION_ANOMALY",
                    severity=EventSeverity.MEDIUM.value,
                    confidence=EventConfidence.MEDIUM.value,
                    risk=15,
                    module=self.name,
                    message=f"High inbound connection surge: {inbound_cnt} active inbound connections.",
                    metadata={"inbound_count": inbound_cnt, "threshold": self.inbound_threshold}
                )
                self.publish_event(event)
                self._last_inbound_alert_time = now

        # Connection Spike
        if total_cnt >= self.spike_threshold:
            if (now - self._last_spike_alert_time) >= self.port_scan_window:
                event = SecurityEvent(
                    category=EventCategory.NETWORK.value,
                    event="CONNECTION_SPIKE",
                    severity=EventSeverity.MEDIUM.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=15,
                    module=self.name,
                    message=f"Connection Spike: Total active connections spiked to {total_cnt}.",
                    metadata={"total_count": total_cnt, "threshold": self.spike_threshold}
                )
                self.publish_event(event)
                self._last_spike_alert_time = now

        # 3. Port Scan Detection
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
                        module=self.name,
                        message=f"Port scan pattern detected from {remote_ip}: attempted {len(ports)} unique ports within {self.port_scan_window}s.",
                        metadata={"source_ip": remote_ip, "port_count": len(ports), "ports": list(ports)[:10]}
                    )
                    self.publish_event(event)
                    self._last_scan_alert_time = now
