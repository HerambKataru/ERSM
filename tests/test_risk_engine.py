"""
Unit tests for RiskEngine scoring, duplicate rate limiting, status labels, and decay.
"""

import unittest
from core.event import SecurityEvent, EventCategory, EventSeverity
from core.risk_engine import RiskEngine


class TestRiskEngine(unittest.TestCase):

    def setUp(self):
        self.risk_engine = RiskEngine({
            "decay_interval_seconds": 1,
            "decay_amount": 5,
            "rate_limit_window_seconds": 60,
            "max_duplicate_points": 2
        })

    def test_risk_scoring_and_status(self):
        self.assertEqual(self.risk_engine.current_risk, 0)
        self.assertEqual(self.risk_engine.status_label, "SAFE")

        # Add HIGH event (+30 points)
        event1 = SecurityEvent(
            category=EventCategory.AUTHENTICATION.value,
            event="AUTH_FAILURE_THRESHOLD",
            severity=EventSeverity.HIGH.value,
            message="Test High Event"
        )
        self.risk_engine.process_event(event1)
        self.assertEqual(self.risk_engine.current_risk, 30)
        self.assertEqual(self.risk_engine.status_label, "WARNING")

    def test_rate_limiting(self):
        # Adding duplicate events should apply diminishing risk returns
        event = SecurityEvent(
            category=EventCategory.NETWORK.value,
            event="PORT_SCAN",
            severity=EventSeverity.HIGH.value,  # Base 30
            message="Test Port Scan"
        )
        r1 = self.risk_engine.process_event(event)  # +30 -> Total 30
        r2 = self.risk_engine.process_event(event)  # Duplicate 1 (+15) -> Total 45
        r3 = self.risk_engine.process_event(event)  # Duplicate 2+ (+3) -> Total 48

        self.assertEqual(r1, 30)
        self.assertEqual(r2, 45)
        self.assertEqual(r3, 48)

    def test_risk_decay(self):
        event = SecurityEvent(
            category=EventCategory.MALWARE.value,
            event="MALWARE_ALERT",
            severity=EventSeverity.CRITICAL.value,  # +50
            message="Test Critical Event"
        )
        self.risk_engine.process_event(event)
        self.assertEqual(self.risk_engine.current_risk, 50)

        # Force decay
        self.risk_engine.force_decay(25)
        self.assertEqual(self.risk_engine.current_risk, 25)
        self.assertEqual(self.risk_engine.status_label, "SAFE")


if __name__ == "__main__":
    unittest.main()
