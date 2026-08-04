"""
Abstract Base Security Monitor for Embedded Runtime Security Monitor (ERSM).
"""

import threading
import time
from typing import Dict, Any, Optional
from core.event import SecurityEvent
from core.event_bus import EventBus
from platform.base_adapter import BasePlatformAdapter
from utils.logger import setup_logger


class BaseMonitor:
    """
    Abstract base thread for background security monitoring tasks.
    """

    def __init__(self, name: str, event_bus: EventBus, platform_adapter: BasePlatformAdapter, config: Dict[str, Any] = None):
        self.name = name
        self.event_bus = event_bus
        self.platform_adapter = platform_adapter
        self.config = config or {}
        self.interval_seconds = self.config.get("interval_seconds", 5)
        self.enabled = self.config.get("enabled", True)
        self.logger = setup_logger(f"ERSM.Monitor.{name}")

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Starts background monitor thread."""
        if not self.enabled:
            self.logger.info(f"Monitor {self.name} is disabled in configuration.")
            return

        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name=f"MonitorThread-{self.name}")
        self._thread.start()
        self.logger.info(f"Monitor {self.name} started (interval: {self.interval_seconds}s).")

    def stop(self) -> None:
        """Stops background monitor thread cleanly."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self.logger.info(f"Monitor {self.name} stopped.")

    def _run_loop(self) -> None:
        """Periodic polling loop."""
        while self._running:
            try:
                self._check()
            except Exception as e:
                self.logger.error(f"Unhandled error in monitor {self.name}: {e}", exc_info=True)
            time.sleep(self.interval_seconds)

    def _check(self) -> None:
        """Subclasses override this method to perform actual monitoring logic."""
        raise NotImplementedError

    def publish_event(self, event: SecurityEvent) -> None:
        """Publishes detected SecurityEvent to EventBus."""
        if self.event_bus:
            self.event_bus.publish(event)
