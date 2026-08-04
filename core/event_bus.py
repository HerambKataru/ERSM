"""
Thread-safe Event Bus for Embedded Runtime Security Monitor (ERSM).
"""

from typing import Callable, List, Dict
import threading
import queue
import logging
from core.event import SecurityEvent

logger = logging.getLogger("ERSM.EventBus")


class EventBus:
    """
    Publisher-subscriber event dispatcher.
    Allows monitors to post events without knowing about transports or risk engines.
    """

    def __init__(self):
        self._subscribers: List[Callable[[SecurityEvent], None]] = []
        self._lock = threading.Lock()
        self._queue: queue.Queue[SecurityEvent] = queue.Queue()
        self._running = False
        self._worker_thread = None

    def subscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Registers a callback function to receive published events."""
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Unregisters a callback function."""
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def publish(self, event: SecurityEvent) -> None:
        """
        Publishes an event to all subscribers synchronously or places into dispatch queue.
        """
        with self._lock:
            subscribers_copy = list(self._subscribers)

        for callback in subscribers_copy:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error executing event subscriber {callback.__name__}: {e}", exc_info=True)

    def start(self) -> None:
        """Starts asynchronous processing queue if needed."""
        self._running = True

    def stop(self) -> None:
        """Stops the event processing queue."""
        self._running = False
