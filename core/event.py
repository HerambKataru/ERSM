"""
Standardized Security Event model for Embedded Runtime Security Monitor (ERSM).
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import json
import socket
import sys
from typing import Any, Dict, Optional


class EventCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK = "NETWORK"
    SYSTEM = "SYSTEM"
    PROCESS = "PROCESS"
    INTEGRITY = "INTEGRITY"
    MALWARE = "MALWARE"
    CORRELATION = "CORRELATION"


class EventSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


def get_default_host() -> str:
    """Returns hostname of local machine."""
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


def get_default_platform() -> str:
    """Returns normalized OS name."""
    if sys.platform.startswith("darwin"):
        return "macOS"
    elif sys.platform.startswith("win"):
        return "Windows"
    elif sys.platform.startswith("linux"):
        return "Linux"
    return sys.platform


@dataclass
class SecurityEvent:
    """
    Standardized security event schema across all ERSM monitors and correlation engines.
    """
    category: str
    event: str
    severity: str
    message: str
    risk: int = 0
    confidence: str = EventConfidence.MEDIUM.value
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    host: str = field(default_factory=get_default_host)
    platform: str = field(default_factory=get_default_platform)
    source: str = "DETECTED_BY_ERSM"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Validate category
        valid_categories = [c.value for c in EventCategory]
        if self.category not in valid_categories:
            raise ValueError(f"Invalid category '{self.category}'. Must be one of {valid_categories}")

        # Validate severity
        valid_severities = [s.value for s in EventSeverity]
        if self.severity not in valid_severities:
            raise ValueError(f"Invalid severity '{self.severity}'. Must be one of {valid_severities}")

        # Validate confidence
        valid_confidences = [c.value for c in EventConfidence]
        if self.confidence not in valid_confidences:
            raise ValueError(f"Invalid confidence '{self.confidence}'. Must be one of {valid_confidences}")

    def to_dict(self) -> Dict[str, Any]:
        """Converts SecurityEvent to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Converts SecurityEvent to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Instantiates SecurityEvent from a dictionary."""
        return cls(
            category=data.get("category", EventCategory.SYSTEM.value),
            event=data.get("event", "UNKNOWN_EVENT"),
            severity=data.get("severity", EventSeverity.INFO.value),
            message=data.get("message", ""),
            risk=data.get("risk", 0),
            confidence=data.get("confidence", EventConfidence.MEDIUM.value),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
            host=data.get("host", get_default_host()),
            platform=data.get("platform", get_default_platform()),
            source=data.get("source", "DETECTED_BY_ERSM"),
            metadata=data.get("metadata", {})
        )
