"""
External Security Tool Integration Interface for Embedded Runtime Security Monitor (ERSM).
Consumes security alerts from external AV engine, host firewalls, and OS security suites.
"""

from typing import Dict, Any
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class ExternalSecurityMonitor(BaseMonitor):
    """
    Ingestion interface for external security alert events.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("ExternalSecurityMonitor", event_bus, platform_adapter, config)

    def _check(self) -> None:
        # Passive monitor — events are injected via ingest_external_alert()
        pass

    def ingest_external_alert(
        self,
        event_type: str,
        severity: str,
        message: str,
        source_provider: str = "External_Antivirus",
        metadata: Dict[str, Any] = None
    ) -> SecurityEvent:
        """
        Ingests an external security tool alert and translates it into standard ERSM format.
        """
        event = SecurityEvent(
            category=EventCategory.MALWARE.value if "MALWARE" in event_type else EventCategory.SYSTEM.value,
            event=event_type,
            severity=severity,
            confidence=EventConfidence.HIGH.value,
            risk=50 if severity == EventSeverity.CRITICAL.value else 30,
            message=message,
            source=f"REPORTED_BY_EXTERNAL_SECURITY_TOOL ({source_provider})",
            metadata=metadata or {}
        )
        self.publish_event(event)
        return event
