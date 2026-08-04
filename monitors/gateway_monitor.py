"""
Gateway Monitoring Module for Embedded Runtime Security Monitor (ERSM).
Monitors default gateway IP and MAC address shifts to detect routing alterations and ARP spoofing.
"""

from typing import Dict, Any, Optional, Tuple
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class GatewayMonitor(BaseMonitor):
    """
    Monitors default network gateway alterations.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("GatewayMonitor", event_bus, platform_adapter, config)
        self._known_gateway_ip: Optional[str] = None
        self._known_gateway_mac: Optional[str] = None
        self._initialized = False

    def _check(self) -> None:
        gateway_ip, gateway_mac = self.platform_adapter.get_default_gateway()

        if not gateway_ip:
            return

        if not self._initialized:
            self._known_gateway_ip = gateway_ip
            self._known_gateway_mac = gateway_mac
            self._initialized = True
            self.logger.info(f"Learned baseline default gateway: {gateway_ip} -> {gateway_mac}")
            return

        # 1. Gateway IP Changed
        if gateway_ip != self._known_gateway_ip:
            event = SecurityEvent(
                category=EventCategory.GATEWAY.value,
                event="GATEWAY_CHANGED",
                severity=EventSeverity.HIGH.value,
                confidence=EventConfidence.HIGH.value,
                risk=30,
                module=self.name,
                message=f"Default Gateway IP changed: Old={self._known_gateway_ip}, New={gateway_ip}",
                metadata={"old_gateway_ip": self._known_gateway_ip, "new_gateway_ip": gateway_ip}
            )
            self.publish_event(event)
            self._known_gateway_ip = gateway_ip

        # 2. Gateway MAC Changed (Possible ARP Poisoning)
        if gateway_mac and self._known_gateway_mac and gateway_mac.lower() != self._known_gateway_mac.lower():
            event = SecurityEvent(
                category=EventCategory.GATEWAY.value,
                event="GATEWAY_MAC_CHANGED",
                severity=EventSeverity.HIGH.value,
                confidence=EventConfidence.MEDIUM.value,
                risk=30,
                module=self.name,
                message=f"Default Gateway MAC address changed unexpectedly (Possible ARP Spoofing): Gateway {gateway_ip} MAC changed from {self._known_gateway_mac} to {gateway_mac}",
                metadata={
                    "gateway_ip": gateway_ip,
                    "old_mac": self._known_gateway_mac,
                    "new_mac": gateway_mac
                }
            )
            self.publish_event(event)
            self._known_gateway_mac = gateway_mac
