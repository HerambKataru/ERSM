"""
Configurable Risk Engine for Embedded Runtime Security Monitor (ERSM).
Implements risk scoring, dynamic decay, rate-limiting, and state mapping.
"""

from datetime import datetime, timezone
import threading
import time
from typing import Dict, List, Tuple
from core.event import SecurityEvent, EventSeverity
from utils.logger import setup_logger

logger = setup_logger("ERSM.RiskEngine")


class RiskEngine:
    """
    Evaluates global security risk score (0 - 100) based on event severity,
    rate-limits rapid duplicates, and applies dynamic time decay.
    """

    DEFAULT_WEIGHTS = {
        EventSeverity.INFO.value: 0,
        EventSeverity.LOW.value: 5,
        EventSeverity.MEDIUM.value: 15,
        EventSeverity.HIGH.value: 30,
        EventSeverity.CRITICAL.value: 50
    }

    def __init__(self, config: Dict = None):
        config = config or {}
        self.weights = config.get("weights", self.DEFAULT_WEIGHTS)
        self.decay_interval = config.get("decay_interval_seconds", 10)
        self.decay_amount = config.get("decay_amount", 2)
        self.rate_limit_window = config.get("rate_limit_window_seconds", 60)
        self.max_duplicate_points = config.get("max_duplicate_points", 2)
        self.thresholds = config.get("thresholds", {
            "SAFE": [0, 29],
            "WARNING": [30, 59],
            "HIGH_RISK": [60, 79],
            "CRITICAL": [80, 100]
        })

        self._current_risk = 0.0
        self._event_history: List[Tuple[float, str]] = []  # List of (timestamp_epoch, event_type)
        self._lock = threading.Lock()
        self._last_decay_time = time.time()

    @property
    def current_risk(self) -> int:
        """Returns rounded current risk score capped between 0 and 100."""
        with self._lock:
            self._apply_decay_internal()
            return int(round(max(0.0, min(100.0, self._current_risk))))

    @property
    def status_label(self) -> str:
        """Returns security status string (SAFE, WARNING, HIGH RISK, CRITICAL)."""
        score = self.current_risk
        if score >= self.thresholds.get("CRITICAL", [80, 100])[0]:
            return "CRITICAL"
        elif score >= self.thresholds.get("HIGH_RISK", [60, 79])[0]:
            return "HIGH RISK"
        elif score >= self.thresholds.get("WARNING", [30, 59])[0]:
            return "WARNING"
        return "SAFE"

    def process_event(self, event: SecurityEvent) -> int:
        """
        Evaluates an incoming event, applies rate-limiting logic,
        updates internal risk score, assigns risk score to event, and returns new risk score.
        """
        with self._lock:
            self._apply_decay_internal()
            now = time.time()

            # Clean old history outside rate limit window
            self._event_history = [
                (ts, ev) for (ts, ev) in self._event_history
                if (now - ts) <= self.rate_limit_window
            ]

            # Count duplicates within window
            recent_same_events = sum(1 for ts, ev in self._event_history if ev == event.event)

            # Calculate base points
            if "risk_override" in event.metadata:
                base_points = event.metadata["risk_override"]
            else:
                base_points = self.weights.get(event.severity, 5)

            # Apply rate limiting multiplier
            if recent_same_events >= self.max_duplicate_points:
                multiplier = 0.1  # Heavy reduction for duplicate flood
            elif recent_same_events > 0:
                multiplier = 0.5  # Moderate reduction for secondary repeat
            else:
                multiplier = 1.0

            added_points = base_points * multiplier
            self._current_risk = min(100.0, self._current_risk + added_points)

            # Record event occurrence
            self._event_history.append((now, event.event))

            assigned_risk = int(round(max(0.0, min(100.0, self._current_risk))))
            event.risk = assigned_risk
            return assigned_risk

    def _apply_decay_internal(self) -> None:
        """Applies dynamic time decay to risk score."""
        now = time.time()
        elapsed = now - self._last_decay_time
        if elapsed >= self.decay_interval:
            intervals_passed = int(elapsed // self.decay_interval)
            decay_total = intervals_passed * self.decay_amount
            self._current_risk = max(0.0, self._current_risk - decay_total)
            self._last_decay_time = now

    def force_decay(self, amount: int = None) -> int:
        """Explicitly applies decay points for testing or periodic cleanup."""
        with self._lock:
            amt = amount if amount is not None else self.decay_amount
            self._current_risk = max(0.0, self._current_risk - amt)
            return int(round(self._current_risk))
