"""
Unit tests for CorrelationEngine rule solving.
"""

import unittest
from core.event import SecurityEvent, EventCategory, EventSeverity
from core.correlation_engine import CorrelationEngine


class TestCorrelationEngine(unittest.TestCase):

    def test_intrusion_correlation_trigger(self):
        engine = CorrelationEngine(window_seconds=60)

        e1 = SecurityEvent(
            category=EventCategory.AUTHENTICATION.value,
            event="AUTH_FAILURE_THRESHOLD",
            severity=EventSeverity.HIGH.value,
            message="Auth failure"
        )
        e2 = SecurityEvent(
            category=EventCategory.PORT.value,
            event="NEW_LISTENING_PORT",
            severity=EventSeverity.MEDIUM.value,
            message="New listening port"
        )
        e3 = SecurityEvent(
            category=EventCategory.PROCESS.value,
            event="PROCESS_NETWORK_ACTIVITY",
            severity=EventSeverity.MEDIUM.value,
            message="Process network connection"
        )

        res1 = engine.process_event(e1)
        res2 = engine.process_event(e2)
        res3 = engine.process_event(e3)

        self.assertEqual(len(res1), 0)
        self.assertEqual(len(res2), 0)
        self.assertEqual(len(res3), 1)
        self.assertEqual(res3[0].event, "POSSIBLE_INTRUSION")
        self.assertEqual(res3[0].category, EventCategory.CORRELATION.value)

    def test_network_attack_correlation_trigger(self):
        engine = CorrelationEngine(window_seconds=60)

        e1 = SecurityEvent(
            category=EventCategory.NETWORK.value,
            event="GATEWAY_MAC_CHANGED",
            severity=EventSeverity.HIGH.value,
            message="ARP MAC shifted"
        )
        e2 = SecurityEvent(
            category=EventCategory.DNS.value,
            event="DNS_SERVER_CHANGED",
            severity=EventSeverity.MEDIUM.value,
            message="DNS server changed"
        )
        e3 = SecurityEvent(
            category=EventCategory.GATEWAY.value,
            event="GATEWAY_CHANGED",
            severity=EventSeverity.HIGH.value,
            message="Default gateway IP changed"
        )

        res1 = engine.process_event(e1)
        res2 = engine.process_event(e2)
        res3 = engine.process_event(e3)

        self.assertEqual(len(res1), 0)
        self.assertEqual(len(res2), 0)
        self.assertEqual(len(res3), 1)
        self.assertEqual(res3[0].event, "POSSIBLE_NETWORK_ATTACK")


if __name__ == "__main__":
    unittest.main()
