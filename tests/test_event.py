"""
Unit tests for SecurityEvent schema validation and JSON serialization.
"""

import unittest
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence


class TestSecurityEvent(unittest.TestCase):

    def test_event_creation_and_validation(self):
        event = SecurityEvent(
            category=EventCategory.SYSTEM.value,
            event="RESOURCE_ANOMALY",
            severity=EventSeverity.LOW.value,
            message="CPU spike test",
            risk=5
        )
        self.assertEqual(event.category, "SYSTEM")
        self.assertEqual(event.severity, "LOW")
        self.assertEqual(event.risk, 5)

    def test_invalid_category(self):
        with self.assertRaises(ValueError):
            SecurityEvent(
                category="INVALID_CAT",
                event="TEST",
                severity="LOW",
                message="test"
            )

    def test_json_serialization(self):
        event = SecurityEvent(
            category=EventCategory.AUTHENTICATION.value,
            event="AUTH_FAILURE",
            severity=EventSeverity.HIGH.value,
            message="Failed login"
        )
        json_str = event.to_json()
        self.assertIn("AUTHENTICATION", json_str)
        self.assertIn("AUTH_FAILURE", json_str)

        reconstructed = SecurityEvent.from_dict(event.to_dict())
        self.assertEqual(reconstructed.event, event.event)


if __name__ == "__main__":
    unittest.main()
