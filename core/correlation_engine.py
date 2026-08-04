"""
Security Correlation Engine for Embedded Runtime Security Monitor (ERSM).
Correlates multi-layer events within configurable sliding time windows.
"""

from datetime import datetime, timezone
import threading
import time
from typing import List, Dict, Callable
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from utils.logger import setup_logger

logger = setup_logger("ERSM.CorrelationEngine")


class CorrelationEngine:
    """
    Tracks sliding window of past events and evaluates multi-event correlation rules.
    """

    def __init__(self, event_bus=None, window_seconds: int = 60, config: Dict = None):
        self.event_bus = event_bus
        self.window_seconds = window_seconds
        self.config = config or {}
        self._history: List[SecurityEvent] = []
        self._lock = threading.Lock()
        self._triggered_correlations: List[str] = []

    def process_event(self, event: SecurityEvent) -> List[SecurityEvent]:
        """
        Ingests a new event, cleans expired events, tests correlation rules,
        and returns any newly generated correlated events.
        """
        # Ignore correlation events to prevent loop recursion
        if event.category == EventCategory.CORRELATION.value:
            return []

        generated_events: List[SecurityEvent] = []
        now = time.time()

        with self._lock:
            self._history.append(event)
            # Retain events within sliding time window
            cutoff = now - self.window_seconds
            self._history = [
                e for e in self._history
                if self._parse_ts(e.timestamp) >= cutoff
            ]

            recent_types = set(e.event for e in self._history)

            # Rule 1: Account / Intrusion Pattern (AUTH_FAILURE_THRESHOLD + NEW_LISTENING_PORT + PROCESS_NETWORK_ACTIVITY)
            rule1_reqs = {"AUTH_FAILURE_THRESHOLD", "NEW_LISTENING_PORT", "PROCESS_NETWORK_ACTIVITY"}
            if (rule1_reqs.issubset(recent_types) or {"AUTH_FAILURE_THRESHOLD", "NEW_NETWORK_DEVICE", "NEW_LISTENING_PORT"}.issubset(recent_types)) and "POSSIBLE_INTRUSION" not in self._triggered_correlations:
                inc_event = SecurityEvent(
                    category=EventCategory.CORRELATION.value,
                    event="POSSIBLE_INTRUSION",
                    severity=EventSeverity.CRITICAL.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=60,
                    module="CorrelationEngine",
                    message="Possible Intrusion Detected: Correlated auth failures, new listening port, and suspicious process network activity.",
                    metadata={"correlated_events": list(recent_types.intersection(rule1_reqs))}
                )
                generated_events.append(inc_event)
                self._triggered_correlations.append("POSSIBLE_INTRUSION")

            # Rule 2: Network Attack Pattern (ARP_ANOMALY/GATEWAY_MAC_CHANGED + DNS_SERVER_CHANGED + GATEWAY_CHANGED)
            net_indicators = {"GATEWAY_MAC_CHANGED", "ARP_MAPPING_CONFLICT", "ARP_ANOMALY"}
            has_arp = bool(net_indicators.intersection(recent_types))
            has_dns = "DNS_SERVER_CHANGED" in recent_types
            has_gw = "GATEWAY_CHANGED" in recent_types

            if (has_arp and has_dns and has_gw) and "POSSIBLE_NETWORK_ATTACK" not in self._triggered_correlations:
                net_event = SecurityEvent(
                    category=EventCategory.CORRELATION.value,
                    event="POSSIBLE_NETWORK_ATTACK",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=50,
                    module="CorrelationEngine",
                    message="Possible Network Attack: Combined ARP anomaly, gateway change, and DNS server alteration detected.",
                    metadata={"correlated_events": ["ARP_ANOMALY", "DNS_SERVER_CHANGED", "GATEWAY_CHANGED"]}
                )
                generated_events.append(net_event)
                self._triggered_correlations.append("POSSIBLE_NETWORK_ATTACK")

            # Rule 3: Network Scan & Flood Attack Pattern
            rule3_reqs = {"PORT_SCAN_SUSPECTED", "CONNECTION_FLOOD_ANOMALY"}
            if rule3_reqs.issubset(recent_types) and "NETWORK_ATTACK_PATTERN" not in self._triggered_correlations:
                atk_event = SecurityEvent(
                    category=EventCategory.CORRELATION.value,
                    event="NETWORK_ATTACK_PATTERN",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=45,
                    module="CorrelationEngine",
                    message="Network Attack Pattern: Combined port scan and connection flood anomaly.",
                    metadata={"correlated_events": list(rule3_reqs)}
                )
                generated_events.append(atk_event)
                self._triggered_correlations.append("NETWORK_ATTACK_PATTERN")

            # Rule 4: System Alteration / Ransomware Indicator (MASS_FILE_CHANGE + PERSISTENCE_CHANGE / PROCESS_RESTART_LOOP)
            if ("MASS_FILE_CHANGE" in recent_types and ("PERSISTENCE_CHANGE" in recent_types or "PROCESS_RESTART_LOOP" in recent_types)) and "SUSPICIOUS_SYSTEM_ALTERATION" not in self._triggered_correlations:
                alt_event = SecurityEvent(
                    category=EventCategory.CORRELATION.value,
                    event="SUSPICIOUS_SYSTEM_ALTERATION",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=50,
                    module="CorrelationEngine",
                    message="Suspicious System Alteration: Rapid file modifications combined with persistence/process anomalies.",
                    metadata={"correlated_events": list(recent_types.intersection({"MASS_FILE_CHANGE", "PERSISTENCE_CHANGE", "PROCESS_RESTART_LOOP"}))}
                )
                generated_events.append(alt_event)
                self._triggered_correlations.append("SUSPICIOUS_SYSTEM_ALTERATION")

            # Custom Configurable Rules
            custom_rules = self.config.get("custom_rules", [])
            for rule in custom_rules:
                rule_id = rule.get("id", rule.get("event"))
                reqs = set(rule.get("required_events", []))
                if reqs and reqs.issubset(recent_types) and rule_id not in self._triggered_correlations:
                    cust_event = SecurityEvent(
                        category=EventCategory.CORRELATION.value,
                        event=rule.get("event", "CORRELATED_EVENT"),
                        severity=rule.get("severity", EventSeverity.HIGH.value),
                        confidence=EventConfidence.HIGH.value,
                        risk=rule.get("risk", 50),
                        module="CorrelationEngine",
                        message=rule.get("message", f"Configured correlation triggered: {rule_id}"),
                        metadata={"correlated_events": list(reqs)}
                    )
                    generated_events.append(cust_event)
                    self._triggered_correlations.append(rule_id)

        # Publish generated correlation events if bus is attached
        if self.event_bus:
            for ge in generated_events:
                self.event_bus.publish(ge)

        return generated_events

    def _parse_ts(self, ts_str: str) -> float:
        """Parses ISO timestamp to epoch timestamp."""
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            return time.time()

