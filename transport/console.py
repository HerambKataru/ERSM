"""
Console Transport module for rendering live security events and dashboard UI in terminal.
"""

from typing import Dict, Any, List
import sys
import threading
import time
from core.event import SecurityEvent
from transport.base_transport import BaseTransport


class ConsoleTransport(BaseTransport):
    """
    Prints security events to stdout with color-coded severities and renders live status dashboard.
    """

    COLORS = {
        "INFO": "\033[94m",      # Blue
        "LOW": "\033[92m",       # Green
        "MEDIUM": "\033[93m",    # Yellow
        "HIGH": "\033[91m",      # Red
        "CRITICAL": "\033[95m",  # Magenta/Purple
        "RESET": "\033[0m",
        "BOLD": "\033[1m"
    }

    def __init__(self, enable_colors: bool = True):
        self.enable_colors = enable_colors
        self._lock = threading.Lock()

    def send_event(self, event: SecurityEvent) -> None:
        """Prints formatted security event line to console."""
        with self._lock:
            if self.enable_colors:
                color = self.COLORS.get(event.severity, self.COLORS["RESET"])
                reset = self.COLORS["RESET"]
                bold = self.COLORS["BOLD"]
                prefix = f"{color}[{event.severity}]{reset}"
                print(f"[{event.timestamp}] {prefix} {bold}{event.event}{reset}: {event.message} (Risk: {event.risk}, Conf: {event.confidence})")
            else:
                print(f"[{event.timestamp}] [{event.severity}] {event.event}: {event.message} (Risk: {event.risk}, Conf: {event.confidence})")
            sys.stdout.flush()

    def render_dashboard(self, status: Dict[str, Any], recent_events: List[SecurityEvent]) -> None:
        """Renders ERSM Host Agent Status Dashboard block."""
        with self._lock:
            st = status.get("status", "SAFE")
            risk = status.get("risk", 0)
            cpu = status.get("cpu", 0)
            ram = status.get("ram", 0)
            net = status.get("network", "ONLINE")
            alerts = status.get("active_alerts", 0)

            print("\n==================================================")
            print("             ERSM HOST AGENT DASHBOARD            ")
            print("==================================================")
            print(f"STATUS: {st}")
            print(f"RISK SCORE: {risk}/100")
            print(f"CPU: {cpu}% | RAM: {ram}% | NETWORK: {net}")
            print(f"Total Alerts Detected: {alerts}")
            print("--------------------------------------------------")
            print("Recent Events:")
            if not recent_events:
                print("  (No security events recorded)")
            else:
                for ev in recent_events[-5:]:
                    print(f"  [{ev.severity}] {ev.event}: {ev.message}")
            print("==================================================\n")
            sys.stdout.flush()
