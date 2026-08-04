"""
Unit tests for CorrelationEngine rule solving.
"""

import unittest
from core.event import SecurityEvent, EventCategory, EventSeverity
from core.correlation_engine import CorrelationEngine


class TestCorrelationEngine(unittest.TestCase):

    def test_correlation_incident_trigger(self):
        engine = CorrelationEngine(window_seconds=60)

        e1 = SecurityEvent(
            category=EventCategory.AUTHENTICATION.value,
            event="AUTH_FAILURE_THRESHOLD",
            severity=EventSeverity.HIGH.value,
            message="Auth failure"
        )
        e2 = SecurityEvent(
            category=EventCategory.NETWORK.value,
            event="NEW_NETWORK_DEVICE",
            severity=EventSeverity.LOW.value,
            message="New dev"
        )
        e3 = SecurityEvent(
            category=EventCategory.NETWORK.value,
            event="NEW_LISTENING_PORT",
            severity=EventSeverity.MEDIUM.value,
            message="New port"
        )

        res1 = engine.process_event(e1)
        res2 = engine.process_event(e2)
        res3 = engine.process_event(e3)

        self.assertEqual(len(res1), 0)
        self.assertEqual(len(res2), 0)
        self.assertEqual(len(res3), 1)
        self.assertEqual(res3[0].event, "CORRELATED_SECURITY_INCIDENT")
        self.assertEqual(res3[0].category, EventCategory.CORRELATION.value)


if __name__ == "__main__":
    unittest.main()
