"""
USB / Device Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors external USB storage and hardware device insertion/removal events.
"""

from typing import Dict, Any, List, Set
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class UsbMonitor(BaseMonitor):
    """
    Monitors external USB devices using platform adapter queries.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("UsbMonitor", event_bus, platform_adapter, config)
        self._known_devices: Set[str] = set()
        self._initialized = False

    def _check(self) -> None:
        devices = self.platform_adapter.get_usb_devices()
        current_names = {d["name"] for d in devices if "name" in d}

        if not self._initialized:
            self._known_devices = current_names
            self._initialized = True
            return

        new_devices = current_names - self._known_devices
        for dev in new_devices:
            event = SecurityEvent(
                category=EventCategory.SYSTEM.value,
                event="NEW_USB_DEVICE",
                severity=EventSeverity.LOW.value,
                confidence=EventConfidence.HIGH.value,
                risk=5,
                message=f"New USB device connected to host: {dev}",
                metadata={"device_name": dev}
            )
            self.publish_event(event)

        self._known_devices = current_names
