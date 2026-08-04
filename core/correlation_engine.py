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
    Tracks sliding window of past events and evaluates multi-event rules.
    """

    def __init__(self, event_bus=None, window_seconds: int = 60):
        self.event_bus = event_bus
        self.window_seconds = window_seconds
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
            # Retain events within window
            cutoff = now - self.window_seconds
            self._history = [
                e for e in self._history
                if self._parse_ts(e.timestamp) >= cutoff
            ]

            recent_types = set(e.event for e in self._history)

            # Rule 1: Account / Network Breach Pattern
            rule1_reqs = {"AUTH_FAILURE_THRESHOLD", "NEW_NETWORK_DEVICE", "NEW_LISTENING_PORT"}
            if rule1_reqs.issubset(recent_types) and "CORRELATED_SECURITY_INCIDENT" not in self._triggered_correlations:
                inc_event = SecurityEvent(
                    category=EventCategory.CORRELATION.value,
                    event="CORRELATED_SECURITY_INCIDENT",
                    severity=EventSeverity.CRITICAL.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=60,
                    message="Correlated Security Incident: Auth failure threshold, new network device, and new listening port detected.",
                    metadata={"correlated_events": list(rule1_reqs)}
                )
                generated_events.append(inc_event)
                self._triggered_correlations.append("CORRELATED_SECURITY_INCIDENT")

            # Rule 2: Network Integrity / Spoofing Pattern
            rule2_reqs = {"ARP_MAPPING_CONFLICT", "DNS_SERVER_CHANGED", "GATEWAY_MAC_CHANGED"}
            # Match if at least 2 of 3 network integrity anomalies occur
            matching_r2 = rule2_reqs.intersection(recent_types)
            if len(matching_r2) >= 2 and "NETWORK_INTEGRITY_INCIDENT" not in self._triggered_correlations:
                net_event = SecurityEvent(
                    category=EventCategory.CORRELATION.value,
                    event="NETWORK_INTEGRITY_INCIDENT",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=50,
                    message="Network Integrity Incident: Multiple network spoofing / config change indicators detected.",
                    metadata={"correlated_events": list(matching_r2)}
                )
                generated_events.append(net_event)
                self._triggered_correlations.append("NETWORK_INTEGRITY_INCIDENT")

            # Rule 3: Network Attack Pattern (Port Scan + Connection Flood)
            rule3_reqs = {"PORT_SCAN_SUSPECTED", "CONNECTION_FLOOD_ANOMALY"}
            if rule3_reqs.issubset(recent_types) and "NETWORK_ATTACK_PATTERN" not in self._triggered_correlations:
                atk_event = SecurityEvent(
                    category=EventCategory.CORRELATION.value,
                    event="NETWORK_ATTACK_PATTERN",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=45,
                    message="Network Attack Pattern: Combined port scan and connection flood anomaly.",
                    metadata={"correlated_events": list(rule3_reqs)}
                )
                generated_events.append(atk_event)
                self._triggered_correlations.append("NETWORK_ATTACK_PATTERN")

            # Rule 4: System Alteration / Ransomware Indicator (Mass File Change + Persistence Change)
            rule4_reqs = {"MASS_FILE_CHANGE", "PERSISTENCE_CHANGE"}
            if rule4_reqs.issubset(recent_types) and "SUSPICIOUS_SYSTEM_ALTERATION" not in self._triggered_correlations:
                alt_event = SecurityEvent(
                    category=EventCategory.CORRELATION.value,
                    event="SUSPICIOUS_SYSTEM_ALTERATION",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=50,
                    message="Suspicious System Alteration: Rapid file modifications combined with persistence changes.",
                    metadata={"correlated_events": list(rule4_reqs)}
                )
                generated_events.append(alt_event)
                self._triggered_correlations.append("SUSPICIOUS_SYSTEM_ALTERATION")

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
