"""
External Security Tool Adapter & Ingestion Engine for Embedded Runtime Security Monitor (ERSM).
Ingests alerts from Windows Defender, macOS XProtect, Linux auditd/ClamAV, and third-party security software.
"""

from typing import Dict, Any, List
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class ExternalSecurityMonitor(BaseMonitor):
    """
    Ingest and normalize external security logs and third-party AV telemetry into standardized ERSM events.
    Enforces distinction: DETECTED_BY_ERSM vs REPORTED_BY_EXTERNAL_SECURITY_TOOL.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("ExternalSecurityMonitor", event_bus, platform_adapter, config)

    def _check(self) -> None:
        """Polls platform adapter for native OS security logs."""
        try:
            alerts = self.platform_adapter.get_external_security_logs()
            for alert in alerts:
                self.ingest_external_alert(
                    event_type=alert.get("event_type", "THREAT_DETECTED"),
                    severity=alert.get("severity", EventSeverity.HIGH.value),
                    message=alert.get("message", "External threat logged by security suite."),
                    source_provider=alert.get("provider", "External Security Suite"),
                    metadata=alert.get("metadata", {})
                )
        except Exception as e:
            self.logger.error(f"Error querying external security logs: {e}")

    def ingest_external_alert(
        self,
        event_type: str,
        severity: str,
        message: str,
        source_provider: str = "External_Antivirus",
        metadata: Dict[str, Any] = None
    ) -> SecurityEvent:
        """
        Ingests external alert and maps event_type to MALWARE_ALERT, THREAT_DETECTED, or SECURITY_WARNING.
        """
        # Map event type to standardized list if necessary
        std_event_type = event_type.upper()
        if "MALWARE" in std_event_type or "VIRUS" in std_event_type or "TROJAN" in std_event_type:
            final_event = "MALWARE_ALERT"
            cat = EventCategory.MALWARE.value
        elif "WARNING" in std_event_type:
            final_event = "SECURITY_WARNING"
            cat = EventCategory.SYSTEM.value
        else:
            final_event = "THREAT_DETECTED"
            cat = EventCategory.SYSTEM.value

        event = SecurityEvent(
            category=cat,
            event=final_event,
            severity=severity,
            confidence=EventConfidence.HIGH.value,
            risk=50 if severity == EventSeverity.CRITICAL.value else 30,
            module=self.name,
            message=f"[{source_provider}] {message}",
            source=f"REPORTED_BY_EXTERNAL_SECURITY_TOOL ({source_provider})",
            metadata=metadata or {}
        )
        self.publish_event(event)
        return event
