"""
Abstract Base Transport interface for outputting events and hardware status packets.
"""

from typing import Dict, Any
from core.event import SecurityEvent


class BaseTransport:
    """
    Abstract transport handler interface.
    """

    def send_event(self, event: SecurityEvent) -> None:
        """Sends or records a standardized SecurityEvent."""
        raise NotImplementedError

    def send_status(self, status: Dict[str, Any]) -> None:
        """Sends real-time status summary packet (e.g. for ESP32 hardware OLED/LED display)."""
        pass

    def start(self) -> None:
        """Starts any transport background workers if necessary."""
        pass

    def stop(self) -> None:
        """Stops transport background workers."""
        pass
