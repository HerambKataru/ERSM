"""
DNS and Network Configuration Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors system DNS server configurations and default gateway shifts.
"""

from typing import Dict, Any, List
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class DnsMonitor(BaseMonitor):
    """
    Monitors system DNS resolver options and alerts on unexpected server modifications.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("DnsMonitor", event_bus, platform_adapter, config)
        self._known_dns_servers: List[str] = []
        self._initialized = False

    def _check(self) -> None:
        current_dns = self.platform_adapter.get_dns_servers()

        if not self._initialized:
            self._known_dns_servers = current_dns
            self._initialized = True
            return

        if current_dns != self._known_dns_servers:
            event = SecurityEvent(
                category=EventCategory.NETWORK.value,
                event="DNS_SERVER_CHANGED",
                severity=EventSeverity.MEDIUM.value,
                confidence=EventConfidence.HIGH.value,
                risk=15,
                message=f"System DNS server configuration changed: Old={self._known_dns_servers}, New={current_dns}",
                metadata={"old_dns": self._known_dns_servers, "new_dns": current_dns}
            )
            self.publish_event(event)
            self._known_dns_servers = current_dns
