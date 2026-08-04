"""
Unit tests for SQLite DatabaseManager storage and query helpers.
"""

import os
import tempfile
import unittest
from core.event import SecurityEvent, EventCategory, EventSeverity
from storage.database import DatabaseManager


class TestDatabaseManager(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_ersm.db")
        self.db = DatabaseManager(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_save_and_query_events(self):
        e1 = SecurityEvent(
            category=EventCategory.NETWORK.value,
            event="PORT_SCAN_SUSPECTED",
            severity=EventSeverity.HIGH.value,
            message="Test Port Scan",
            risk=30,
            module="NetworkMonitor"
        )
        e2 = SecurityEvent(
            category=EventCategory.USB.value,
            event="UNKNOWN_USB_DEVICE",
            severity=EventSeverity.MEDIUM.value,
            message="Test USB",
            risk=15,
            module="UsbMonitor"
        )

        rowid1 = self.db.save_event(e1)
        rowid2 = self.db.save_event(e2)

        self.assertGreater(rowid1, 0)
        self.assertGreater(rowid2, 0)

        # Recent events
        recent = self.db.get_recent_events(10)
        self.assertEqual(len(recent), 2)
        self.assertEqual(recent[0]["event"], "UNKNOWN_USB_DEVICE")

        # Highest risk events
        high_risk = self.db.get_highest_risk_events(10)
        self.assertEqual(high_risk[0]["event"], "PORT_SCAN_SUSPECTED")
        self.assertEqual(high_risk[0]["risk"], 30)

        # Query by Category
        usb_events = self.db.get_events_by_category("USB")
        self.assertEqual(len(usb_events), 1)
        self.assertEqual(usb_events[0]["event"], "UNKNOWN_USB_DEVICE")

        # Query Daily Counts
        daily = self.db.get_daily_counts()
        self.assertGreater(len(daily), 0)
        self.assertEqual(daily[0]["count"], 2)


if __name__ == "__main__":
    unittest.main()
