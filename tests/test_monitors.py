"""
Unit tests for SystemMonitor duration-based anomaly rules and ARP/Network monitors.
"""

import unittest
from unittest.mock import MagicMock
from core.event import SecurityEvent
from monitors.system_monitor import SystemMonitor
from monitors.arp_monitor import ArpMonitor


class TestMonitors(unittest.TestCase):

    def test_system_monitor_duration_spike(self):
        mock_bus = MagicMock()
        mock_adapter = MagicMock()
        monitor = SystemMonitor(
            event_bus=mock_bus,
            platform_adapter=mock_adapter,
            config={
                "cpu_threshold_percent": 90.0,
                "cpu_duration_seconds": 1  # 1s duration for fast unit testing
            }
        )

        # Trigger check - single spike should not publish event immediately
        monitor._check()
        self.assertEqual(mock_bus.publish.call_count, 0)

    def test_arp_monitor_gateway_change(self):
        mock_bus = MagicMock()
        mock_adapter = MagicMock()

        # Step 1: Initial learning
        mock_adapter.get_default_gateway.return_value = ("192.168.1.1", "00:11:22:33:44:55")
        mock_adapter.get_arp_table.return_value = {"192.168.1.1": "00:11:22:33:44:55"}

        monitor = ArpMonitor(event_bus=mock_bus, platform_adapter=mock_adapter)
        monitor._check()
        self.assertEqual(mock_bus.publish.call_count, 0)

        # Step 2: Gateway MAC unexpected change
        mock_adapter.get_default_gateway.return_value = ("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        mock_adapter.get_arp_table.return_value = {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}

        monitor._check()
        self.assertEqual(mock_bus.publish.call_count, 1)
        event: SecurityEvent = mock_bus.publish.call_args[0][0]
        self.assertEqual(event.event, "GATEWAY_MAC_CHANGED")
        self.assertEqual(event.category, "NETWORK")


if __name__ == "__main__":
    unittest.main()
