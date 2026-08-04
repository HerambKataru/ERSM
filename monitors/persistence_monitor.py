"""
Persistence Change Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors system autostart/persistence configurations across OS platforms.
"""

import os
from typing import Dict, Any, Set
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class PersistenceMonitor(BaseMonitor):
    """
    Monitors system and user startup/autostart locations for unexpected changes.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("PersistenceMonitor", event_bus, platform_adapter, config)
        self._known_entries: Set[str] = set()
        self._initialized = False

    def _check(self) -> None:
        locations = self.platform_adapter.get_persistence_locations()
        current_entries: Set[str] = set()

        for loc in locations:
            if os.path.isdir(loc):
                try:
                    for item in os.listdir(loc):
                        full_p = os.path.join(loc, item)
                        current_entries.add(full_p)
                except Exception:
                    pass

        if not self._initialized:
            self._known_entries = current_entries
            self._initialized = True
            return

        new_entries = current_entries - self._known_entries
        for entry in new_entries:
            event = SecurityEvent(
                category=EventCategory.SYSTEM.value,
                event="PERSISTENCE_CHANGE",
                severity=EventSeverity.HIGH.value,
                confidence=EventConfidence.MEDIUM.value,
                risk=30,
                message=f"Persistence entry added or modified: {entry}",
                metadata={"path": entry}
            )
            self.publish_event(event)

        self._known_entries = current_entries
