"""
Network Device Discovery Monitor for Embedded Runtime Security Monitor (ERSM).
Maintains local network inventory via ARP table inspection, detecting new device joiners and disconnections.
"""

from typing import Dict, Any, Set
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class NetworkDeviceMonitor(BaseMonitor):
    """
    Monitors local subnet host inventory via platform ARP telemetry.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("NetworkDeviceMonitor", event_bus, platform_adapter, config)
        self._known_devices: Dict[str, str] = {}  # IP -> MAC
        self._initialized = False

    def _check(self) -> None:
        current_arp = self.platform_adapter.get_arp_table()  # Dict[ip, mac]

        if not self._initialized:
            self._known_devices = current_arp
            self._initialized = True
            self.logger.info(f"Initialized network device inventory with {len(current_arp)} host(s).")
            return

        current_ips = set(current_arp.keys())
        known_ips = set(self._known_devices.keys())

        # 1. New Device / MAC / IP Discovery
        new_ips = current_ips - known_ips
        for ip in new_ips:
            mac = current_arp[ip]
            event = SecurityEvent(
                category=EventCategory.DEVICE.value,
                event="NEW_NETWORK_DEVICE",
                severity=EventSeverity.LOW.value,
                confidence=EventConfidence.HIGH.value,
                risk=5,
                module=self.name,
                message=f"New network device discovered on subnet: IP={ip}, MAC={mac}",
                metadata={"ip": ip, "mac": mac}
            )
            self.publish_event(event)

        # 2. Disconnected Devices
        disconnected_ips = known_ips - current_ips
        for ip in disconnected_ips:
            old_mac = self._known_devices[ip]
            event = SecurityEvent(
                category=EventCategory.DEVICE.value,
                event="DEVICE_REMOVED",
                severity=EventSeverity.INFO.value,
                confidence=EventConfidence.MEDIUM.value,
                risk=0,
                module=self.name,
                message=f"Network device disconnected from subnet: IP={ip}, MAC={old_mac}",
                metadata={"ip": ip, "mac": old_mac}
            )
            self.publish_event(event)

        self._known_devices = current_arp
