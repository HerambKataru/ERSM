"""
Unit tests for new ERSM monitoring modules: USB, Firewall, DNS, Gateway, Network Device, Process, File Activity, and External Security.
"""

import unittest
from unittest.mock import MagicMock
import os
import tempfile
import json

from core.event import SecurityEvent, EventCategory
from core.event_bus import EventBus
from monitors.usb_monitor import UsbMonitor
from monitors.firewall_monitor import FirewallMonitor
from monitors.dns_monitor import DnsMonitor
from monitors.gateway_monitor import GatewayMonitor
from monitors.network_device_monitor import NetworkDeviceMonitor
from monitors.external_security_monitor import ExternalSecurityMonitor
from monitors.process_monitor import ProcessMonitor
from monitors.file_integrity_monitor import FileIntegrityMonitor


class TestNewMonitors(unittest.TestCase):

    def test_usb_monitor_insertion_and_trust(self):
        mock_bus = MagicMock()
        mock_adapter = MagicMock()

        # Initial check
        mock_adapter.get_usb_devices_detailed.return_value = []
        usb_mon = UsbMonitor(mock_bus, mock_adapter, config={"trusted_vendors": ["SanDisk"]})
        usb_mon._check()
        self.assertEqual(mock_bus.publish.call_count, 0)

        # Insertion of unknown USB device
        mock_adapter.get_usb_devices_detailed.return_value = [{
            "name": "Rogue Flash Drive",
            "vendor": "UnknownVendor",
            "product_id": "0x1234",
            "serial": "112233",
            "is_storage": True
        }]
        usb_mon._check()
        # Should publish USB_CONNECTED and UNKNOWN_USB_DEVICE
        self.assertEqual(mock_bus.publish.call_count, 2)
        events = [call[0][0] for call in mock_bus.publish.call_args_list]
        event_types = [e.event for e in events]
        self.assertIn("USB_CONNECTED", event_types)
        self.assertIn("UNKNOWN_USB_DEVICE", event_types)

    def test_firewall_monitor_disabled(self):
        mock_bus = MagicMock()
        mock_adapter = MagicMock()

        # Baseline enabled
        mock_adapter.get_firewall_status.return_value = {"enabled": True, "config_changed": False, "blocked_events": []}
        fw_mon = FirewallMonitor(mock_bus, mock_adapter)
        fw_mon._check()
        self.assertEqual(mock_bus.publish.call_count, 0)

        # Disable firewall
        mock_adapter.get_firewall_status.return_value = {"enabled": False, "config_changed": False, "blocked_events": []}
        fw_mon._check()
        self.assertEqual(mock_bus.publish.call_count, 1)
        event: SecurityEvent = mock_bus.publish.call_args[0][0]
        self.assertEqual(event.event, "FIREWALL_DISABLED")
        self.assertEqual(event.category, EventCategory.FIREWALL.value)

    def test_dns_monitor_server_changed(self):
        mock_bus = MagicMock()
        mock_adapter = MagicMock()

        # Initial DNS
        mock_adapter.get_dns_servers.return_value = ["8.8.8.8"]
        dns_mon = DnsMonitor(mock_bus, mock_adapter)
        dns_mon._check()
        self.assertEqual(mock_bus.publish.call_count, 0)

        # Changed DNS
        mock_adapter.get_dns_servers.return_value = ["1.1.1.1"]
        dns_mon._check()
        self.assertEqual(mock_bus.publish.call_count, 1)
        event: SecurityEvent = mock_bus.publish.call_args[0][0]
        self.assertEqual(event.event, "DNS_SERVER_CHANGED")

    def test_gateway_monitor_changed(self):
        mock_bus = MagicMock()
        mock_adapter = MagicMock()

        # Initial Gateway
        mock_adapter.get_default_gateway.return_value = ("192.168.1.1", "00:11:22:33:44:55")
        gw_mon = GatewayMonitor(mock_bus, mock_adapter)
        gw_mon._check()
        self.assertEqual(mock_bus.publish.call_count, 0)

        # Changed Gateway IP
        mock_adapter.get_default_gateway.return_value = ("10.0.0.1", "00:11:22:33:44:55")
        gw_mon._check()
        self.assertEqual(mock_bus.publish.call_count, 1)
        event: SecurityEvent = mock_bus.publish.call_args[0][0]
        self.assertEqual(event.event, "GATEWAY_CHANGED")

    def test_network_device_monitor_discovery(self):
        mock_bus = MagicMock()
        mock_adapter = MagicMock()

        # Initial ARP
        mock_adapter.get_arp_table.return_value = {"192.168.1.1": "00:11:22:33:44:55"}
        dev_mon = NetworkDeviceMonitor(mock_bus, mock_adapter)
        dev_mon._check()
        self.assertEqual(mock_bus.publish.call_count, 0)

        # New IP on subnet
        mock_adapter.get_arp_table.return_value = {
            "192.168.1.1": "00:11:22:33:44:55",
            "192.168.1.50": "aa:bb:cc:dd:ee:ff"
        }
        dev_mon._check()
        self.assertEqual(mock_bus.publish.call_count, 1)
        event: SecurityEvent = mock_bus.publish.call_args[0][0]
        self.assertEqual(event.event, "NEW_NETWORK_DEVICE")

    def test_external_security_monitor_ingest(self):
        mock_bus = MagicMock()
        mock_adapter = MagicMock()

        ext_mon = ExternalSecurityMonitor(mock_bus, mock_adapter)
        ext_mon.ingest_external_alert(
            event_type="MALWARE_ALERT",
            severity="CRITICAL",
            message="Test Virus Signature Matched",
            source_provider="Windows Defender"
        )
        self.assertEqual(mock_bus.publish.call_count, 1)
        event: SecurityEvent = mock_bus.publish.call_args[0][0]
        self.assertEqual(event.event, "MALWARE_ALERT")
        self.assertEqual(event.source, "REPORTED_BY_EXTERNAL_SECURITY_TOOL (Windows Defender)")


if __name__ == "__main__":
    unittest.main()
