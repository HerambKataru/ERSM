"""
Firewall Security Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors firewall status (enabled/disabled), configuration changes, and repeated connection block events.
"""

import time
from typing import Dict, Any, List
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class FirewallMonitor(BaseMonitor):
    """
    Monitors OS firewall state and generates alerts for firewall disabling or configuration changes.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("FirewallMonitor", event_bus, platform_adapter, config)
        self.block_threshold = self.config.get("block_event_threshold", 5)
        self.block_window = self.config.get("block_window_seconds", 30)

        self._last_state: bool = True  # True = enabled
        self._initialized = False
        self._block_history: List[float] = []
        self._last_block_alert_time = 0.0

    def _check(self) -> None:
        now = time.time()
        fw_status = self.platform_adapter.get_firewall_status()
        is_enabled = fw_status.get("enabled", True)
        config_changed = fw_status.get("config_changed", False)
        blocked_events = fw_status.get("blocked_events", [])

        if not self._initialized:
            self._last_state = is_enabled
            self._initialized = True
            return

        # 1. Firewall Disabled Alert
        if not is_enabled and self._last_state:
            event = SecurityEvent(
                category=EventCategory.FIREWALL.value,
                event="FIREWALL_DISABLED",
                severity=EventSeverity.CRITICAL.value,
                confidence=EventConfidence.HIGH.value,
                risk=50,
                module=self.name,
                message="SECURITY WARNING: System firewall has been disabled!",
                metadata={"platform": self.platform_adapter.get_platform_name()}
            )
            self.publish_event(event)

        self._last_state = is_enabled

        # 2. Firewall Configuration Changed
        if config_changed:
            event = SecurityEvent(
                category=EventCategory.FIREWALL.value,
                event="FIREWALL_CONFIGURATION_CHANGED",
                severity=EventSeverity.MEDIUM.value,
                confidence=EventConfidence.HIGH.value,
                risk=15,
                module=self.name,
                message="Firewall policy rules or configuration modified.",
                metadata={"platform": self.platform_adapter.get_platform_name()}
            )
            self.publish_event(event)

        # 3. Repeated Blocked Connection Events
        if blocked_events:
            for _ in blocked_events:
                self._block_history.append(now)

            cutoff = now - self.block_window
            self._block_history = [ts for ts in self._block_history if ts >= cutoff]

            if len(self._block_history) >= self.block_threshold:
                if (now - self._last_block_alert_time) >= self.block_window:
                    event = SecurityEvent(
                        category=EventCategory.FIREWALL.value,
                        event="FIREWALL_BLOCK_EVENT",
                        severity=EventSeverity.MEDIUM.value,
                        confidence=EventConfidence.HIGH.value,
                        risk=15,
                        module=self.name,
                        message=f"Firewall Block Surge: {len(self._block_history)} connections blocked by firewall within {self.block_window}s.",
                        metadata={"blocked_count": len(self._block_history), "window_seconds": self.block_window}
                    )
                    self.publish_event(event)
                    self._last_block_alert_time = now
