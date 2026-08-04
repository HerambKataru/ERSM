"""
DNS Monitoring Module for Embedded Runtime Security Monitor (ERSM).
Monitors DNS server configurations, detects unexpected DNS resolvers, query bursts, and repeated resolution failures.
"""

import time
from typing import Dict, Any, List, Set
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class DnsMonitor(BaseMonitor):
    """
    Monitors system DNS configuration, unexpected DNS server alterations, resolution failures, and bursts.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("DnsMonitor", event_bus, platform_adapter, config)
        self.trusted_dns_servers: Set[str] = set(self.config.get("trusted_dns_servers", []))
        self.failure_threshold = self.config.get("failure_threshold", 5)
        self.burst_threshold = self.config.get("burst_threshold", 50)
        self.time_window = self.config.get("time_window_seconds", 30)

        self._known_dns_servers: List[str] = []
        self._initialized = False
        self._failure_count = 0
        self._recent_query_timestamps: List[float] = []

    def _check(self) -> None:
        current_dns = self.platform_adapter.get_dns_servers()

        if not self._initialized:
            self._known_dns_servers = current_dns
            self._initialized = True
            return

        # 1. DNS Server Changes
        if current_dns != self._known_dns_servers:
            event = SecurityEvent(
                category=EventCategory.DNS.value,
                event="DNS_SERVER_CHANGED",
                severity=EventSeverity.MEDIUM.value,
                confidence=EventConfidence.HIGH.value,
                risk=15,
                module=self.name,
                message=f"System DNS server configuration changed: Old={self._known_dns_servers}, New={current_dns}",
                metadata={"old_dns": self._known_dns_servers, "new_dns": current_dns}
            )
            self.publish_event(event)
            self._known_dns_servers = current_dns

        # 2. Unexpected DNS Configuration Detection
        if self.trusted_dns_servers:
            untrusted = set(current_dns) - self.trusted_dns_servers
            if untrusted:
                event = SecurityEvent(
                    category=EventCategory.DNS.value,
                    event="DNS_ANOMALY",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=30,
                    module=self.name,
                    message=f"Unexpected/Untrusted DNS server configured: {list(untrusted)}",
                    metadata={"untrusted_dns": list(untrusted), "configured_dns": current_dns}
                )
                self.publish_event(event)

    def record_dns_failure(self, domain: str = "") -> SecurityEvent:
        """
        Helper function to report a failed DNS resolution event.
        """
        self._failure_count += 1
        if self._failure_count >= self.failure_threshold:
            event = SecurityEvent(
                category=EventCategory.DNS.value,
                event="DNS_FAILURE",
                severity=EventSeverity.MEDIUM.value,
                confidence=EventConfidence.HIGH.value,
                risk=15,
                module=self.name,
                message=f"Repeated DNS resolution failure detected ({self._failure_count} consecutive failures). Target domain: {domain}",
                metadata={"failure_count": self._failure_count, "domain": domain}
            )
            self.publish_event(event)
            self._failure_count = 0
            return event
        return None

    def record_dns_query_burst(self, query_count: int) -> SecurityEvent:
        """
        Helper function to report large DNS request bursts.
        """
        if query_count >= self.burst_threshold:
            event = SecurityEvent(
                category=EventCategory.DNS.value,
                event="DNS_ANOMALY",
                severity=EventSeverity.HIGH.value,
                confidence=EventConfidence.HIGH.value,
                risk=30,
                module=self.name,
                message=f"Large DNS request burst detected: {query_count} queries in short window.",
                metadata={"query_count": query_count, "threshold": self.burst_threshold}
            )
            self.publish_event(event)
            return event
        return None
