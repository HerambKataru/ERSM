"""
Global State Manager for Embedded Runtime Security Monitor (ERSM).
Maintains real-time status telemetry and alert stats formatted for ESP32 hardware streaming.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
from typing import Dict, Any, List
import psutil
from core.event import SecurityEvent


class StateManager:
    """
    Tracks application runtime metrics, CPU/RAM stats, risk score, alert counters,
    and recent security events for terminal rendering and ESP32 hardware status packets.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.cpu_percent: float = 0.0
        self.ram_percent: float = 0.0
        self.network_status: str = "ONLINE"
        self.risk_score: int = 0
        self.status_label: str = "SAFE"
        self.alert_count: int = 0
        self.recent_events: List[SecurityEvent] = []
        self.last_event_name: str = "NONE"

    def update_telemetry(self, cpu: float = None, ram: float = None, network: str = None) -> None:
        """Updates CPU, RAM, and network interface status."""
        with self._lock:
            if cpu is None or ram is None:
                self.cpu_percent = psutil.cpu_percent(interval=None)
                self.ram_percent = psutil.virtual_memory().percent
            else:
                self.cpu_percent = cpu
                self.ram_percent = ram

            if network is not None:
                self.network_status = network

    def update_risk(self, risk_score: int, status_label: str) -> None:
        """Updates current risk score and label."""
        with self._lock:
            self.risk_score = risk_score
            self.status_label = status_label

    def record_event(self, event: SecurityEvent) -> None:
        """Records a new security event into recent list and updates counters."""
        with self._lock:
            self.alert_count += 1
            self.last_event_name = event.event
            self.recent_events.append(event)
            if len(self.recent_events) > 10:
                self.recent_events.pop(0)

    def get_status_summary(self) -> Dict[str, Any]:
        """
        Returns JSON-serializable status payload for terminal display and ESP32 USB streaming.
        """
        with self._lock:
            return {
                "status": self.status_label,
                "risk": self.risk_score,
                "cpu": int(round(self.cpu_percent)),
                "ram": int(round(self.ram_percent)),
                "network": self.network_status,
                "active_alerts": self.alert_count,
                "last_event": self.last_event_name,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
