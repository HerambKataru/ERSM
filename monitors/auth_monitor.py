"""
Authentication Security Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors OS log streams for repeated login failures and suspicious authentication behavior.
"""

import time
from typing import Dict, Any, List
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class AuthMonitor(BaseMonitor):
    """
    Monitors OS authentication events and triggers alerts when failure thresholds are exceeded.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("AuthMonitor", event_bus, platform_adapter, config)
        self.failure_threshold = self.config.get("failure_threshold", 5)
        self.time_window = self.config.get("time_window_seconds", 60)
        self._last_alert_time = 0.0

    def _check(self) -> None:
        now = time.time()
        # Query platform adapter for auth failures in time window
        failures = self.platform_adapter.get_auth_failures(self.time_window)
        failure_count = len(failures)

        if failure_count >= self.failure_threshold:
            # Throttle repeated alert bursts within time window
            if (now - self._last_alert_time) >= self.time_window:
                event = SecurityEvent(
                    category=EventCategory.AUTHENTICATION.value,
                    event="AUTH_FAILURE_THRESHOLD",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=30,
                    message=f"Authentication Failure Threshold Exceeded: {failure_count} failures within {self.time_window} seconds.",
                    metadata={
                        "failure_count": failure_count,
                        "threshold": self.failure_threshold,
                        "window_seconds": self.time_window
                    }
                )
                self.publish_event(event)
                self._last_alert_time = now
