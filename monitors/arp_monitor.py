"""
ARP Security Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors local ARP table for gateway MAC changes, IP/MAC conflicts, and ARP spoofing indicators.
"""

import time
from typing import Dict, Any, Optional
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class ArpMonitor(BaseMonitor):
    """
    Monitors local ARP table to detect default gateway MAC spoofing and IP collision anomalies.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("ArpMonitor", event_bus, platform_adapter, config)
        self._gateway_ip: Optional[str] = None
        self._expected_gateway_mac: Optional[str] = None
        self._previous_arp_table: Dict[str, str] = {}
        self._initialized = False

    def _check(self) -> None:
        gw_ip, gw_mac = self.platform_adapter.get_default_gateway()
        current_arp = self.platform_adapter.get_arp_table()

        if not self._initialized:
            if gw_ip and gw_mac:
                self._gateway_ip = gw_ip
                self._expected_gateway_mac = gw_mac
                self.logger.info(f"Learned default gateway baseline: {gw_ip} -> {gw_mac}")
            self._previous_arp_table = current_arp
            self._initialized = True
            return

        # 1. Gateway MAC Change Detection
        if gw_ip and gw_mac:
            if self._gateway_ip is None:
                self._gateway_ip = gw_ip
                self._expected_gateway_mac = gw_mac
            elif gw_ip == self._gateway_ip and self._expected_gateway_mac and gw_mac != self._expected_gateway_mac:
                event = SecurityEvent(
                    category=EventCategory.NETWORK.value,
                    event="GATEWAY_MAC_CHANGED",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.MEDIUM.value,
                    risk=30,
                    message=f"Possible ARP Spoofing: Default gateway {gw_ip} MAC changed from {self._expected_gateway_mac} to {gw_mac}.",
                    metadata={
                        "gateway_ip": gw_ip,
                        "old_mac": self._expected_gateway_mac,
                        "new_mac": gw_mac
                    }
                )
                self.publish_event(event)
                # Update expected to avoid continuous alert spam
                self._expected_gateway_mac = gw_mac

        # 2. Conflicting IP-to-MAC Mappings (Multiple IPs mapped to same non-multicast MAC)
        mac_to_ips: Dict[str, List[str]] = {}
        for ip, mac in current_arp.items():
            # Filter out broadcast/multicast MACs
            if mac in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                continue
            if mac not in mac_to_ips:
                mac_to_ips[mac] = []
            mac_to_ips[mac].append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                # Same MAC claiming multiple distinct IP addresses
                event = SecurityEvent(
                    category=EventCategory.NETWORK.value,
                    event="ARP_MAPPING_CONFLICT",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.MEDIUM.value,
                    risk=30,
                    message=f"ARP Mapping Conflict: MAC address {mac} is associated with multiple IPs: {', '.join(ips)}.",
                    metadata={"mac": mac, "conflicting_ips": ips}
                )
                self.publish_event(event)

        self._previous_arp_table = current_arp
