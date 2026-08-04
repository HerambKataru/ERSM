"""
USB Security Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors USB insertion, removal, trusted/unknown classification, device details, and malware flags.
"""

from typing import Dict, Any, List, Set
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class UsbMonitor(BaseMonitor):
    """
    Monitors USB device connections, insertions, removals, and evaluates device trust status.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("UsbMonitor", event_bus, platform_adapter, config)
        self.trusted_vendors: Set[str] = set(self.config.get("trusted_vendors", []))
        self.trusted_devices: Set[str] = set(self.config.get("trusted_devices", []))
        self.trusted_serials: Set[str] = set(self.config.get("trusted_serials", []))

        self._known_device_map: Dict[str, Dict[str, Any]] = {}  # device_name -> device_info
        self._initialized = False

    def _check(self) -> None:
        devices = self.platform_adapter.get_usb_devices_detailed()
        current_map = {d.get("name", "Unknown USB"): d for d in devices}

        if not self._initialized:
            self._known_device_map = current_map
            self._initialized = True
            return

        current_names = set(current_map.keys())
        known_names = set(self._known_device_map.keys())

        # 1. Insertion Detection
        inserted = current_names - known_names
        for name in inserted:
            dev_info = current_map[name]
            vendor = dev_info.get("vendor", "Unknown Vendor")
            product_id = dev_info.get("product_id", "0x0000")
            serial = dev_info.get("serial", "N/A")
            is_storage = dev_info.get("is_storage", False)

            # Standard insertion event
            conn_event = SecurityEvent(
                category=EventCategory.USB.value,
                event="USB_CONNECTED",
                severity=EventSeverity.LOW.value,
                confidence=EventConfidence.HIGH.value,
                risk=5,
                module=self.name,
                message=f"USB device connected: {name} (Vendor: {vendor}, PID: {product_id}, Storage: {is_storage})",
                metadata={
                    "device_name": name,
                    "vendor": vendor,
                    "product_id": product_id,
                    "serial": serial,
                    "is_storage": is_storage
                }
            )
            self.publish_event(conn_event)

            # Trust Classification Logic
            is_trusted = (
                name in self.trusted_devices or
                vendor in self.trusted_vendors or
                serial in self.trusted_serials
            )

            if is_trusted:
                trust_event = SecurityEvent(
                    category=EventCategory.USB.value,
                    event="TRUSTED_USB_DEVICE",
                    severity=EventSeverity.INFO.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=0,
                    module=self.name,
                    message=f"Trusted USB device verified: {name}",
                    metadata={"device_name": name, "vendor": vendor}
                )
                self.publish_event(trust_event)
            else:
                unk_event = SecurityEvent(
                    category=EventCategory.USB.value,
                    event="UNKNOWN_USB_DEVICE",
                    severity=EventSeverity.MEDIUM.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=15,
                    module=self.name,
                    message=f"Unknown/Untrusted USB device attached: {name} (Vendor: {vendor}, Serial: {serial})",
                    metadata={"device_name": name, "vendor": vendor, "serial": serial}
                )
                self.publish_event(unk_event)

        # 2. Removal Detection
        removed = known_names - current_names
        for name in removed:
            old_info = self._known_device_map[name]
            rem_event = SecurityEvent(
                category=EventCategory.USB.value,
                event="USB_REMOVED",
                severity=EventSeverity.INFO.value,
                confidence=EventConfidence.HIGH.value,
                risk=0,
                module=self.name,
                message=f"USB device removed from host: {name}",
                metadata={"device_name": name, "vendor": old_info.get("vendor")}
            )
            self.publish_event(rem_event)

        self._known_device_map = current_map

    def report_usb_malware(self, device_name: str, threat_info: str) -> SecurityEvent:
        """
        Helper method to generate USB_MALWARE_ALERT when external security software reports USB-borne malware.
        """
        mal_event = SecurityEvent(
            category=EventCategory.USB.value,
            event="USB_MALWARE_ALERT",
            severity=EventSeverity.CRITICAL.value,
            confidence=EventConfidence.HIGH.value,
            risk=50,
            module=self.name,
            source="REPORTED_BY_EXTERNAL_SECURITY_TOOL",
            message=f"Antivirus reported malware payload originating from USB device '{device_name}': {threat_info}",
            metadata={"device_name": device_name, "threat_info": threat_info}
        )
        self.publish_event(mal_event)
        return mal_event
