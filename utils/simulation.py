"""
Simulation Engine for Embedded Runtime Security Monitor (ERSM).
Safely generates mock security events for testing detection rules, risk engine, database, and transports.
"""

from typing import Dict, Any, Optional
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from core.event_bus import EventBus
from utils.logger import setup_logger

logger = setup_logger("ERSM.Simulation")

SIMULATED_EVENTS = {
    "AUTH_FAILURE": SecurityEvent(
        category=EventCategory.AUTHENTICATION.value,
        event="AUTH_FAILURE_THRESHOLD",
        severity=EventSeverity.HIGH.value,
        confidence=EventConfidence.HIGH.value,
        risk=30,
        message="[SIMULATED] 5 consecutive failed login attempts detected within 30 seconds.",
        source="SIMULATOR",
        metadata={"simulated": True, "attempts": 5}
    ),
    "ARP_ANOMALY": SecurityEvent(
        category=EventCategory.NETWORK.value,
        event="GATEWAY_MAC_CHANGED",
        severity=EventSeverity.HIGH.value,
        confidence=EventConfidence.MEDIUM.value,
        risk=30,
        message="[SIMULATED] Possible ARP Spoofing: Default gateway 192.168.1.1 MAC changed unexpectedly.",
        source="SIMULATOR",
        metadata={"simulated": True, "old_mac": "00:11:22:33:44:55", "new_mac": "aa:bb:cc:dd:ee:ff"}
    ),
    "PORT_SCAN": SecurityEvent(
        category=EventCategory.NETWORK.value,
        event="PORT_SCAN_SUSPECTED",
        severity=EventSeverity.HIGH.value,
        confidence=EventConfidence.HIGH.value,
        risk=30,
        message="[SIMULATED] Rapid port scan pattern detected from 192.168.1.150 across 25 destination ports.",
        source="SIMULATOR",
        metadata={"simulated": True, "source_ip": "192.168.1.150", "ports_scanned": 25}
    ),
    "FILE_INTEGRITY_CHANGE": SecurityEvent(
        category=EventCategory.INTEGRITY.value,
        event="FILE_INTEGRITY_CHANGE",
        severity=EventSeverity.HIGH.value,
        confidence=EventConfidence.HIGH.value,
        risk=30,
        message="[SIMULATED] SHA-256 baseline hash mismatch detected for monitored file /etc/hosts.",
        source="SIMULATOR",
        metadata={"simulated": True, "path": "/etc/hosts"}
    ),
    "RESOURCE_ANOMALY": SecurityEvent(
        category=EventCategory.SYSTEM.value,
        event="RESOURCE_ANOMALY",
        severity=EventSeverity.LOW.value,
        confidence=EventConfidence.LOW.value,
        risk=5,
        message="[SIMULATED] Sustained abnormal CPU utilization: 96.5% for 45 seconds.",
        source="SIMULATOR",
        metadata={"simulated": True, "cpu_percent": 96.5}
    ),
    "MALWARE_ALERT": SecurityEvent(
        category=EventCategory.MALWARE.value,
        event="MALWARE_ALERT",
        severity=EventSeverity.CRITICAL.value,
        confidence=EventConfidence.HIGH.value,
        risk=50,
        message="[SIMULATED] External Antivirus reported Trojan signature matched in temp payload.",
        source="SIMULATOR",
        metadata={"simulated": True, "signature": "Win32.Trojan.Generic"}
    )
}


def trigger_simulation_event(event_name: str, event_bus: EventBus) -> Optional[SecurityEvent]:
    """
    Generates and dispatches a simulated security event.
    """
    event_key = event_name.upper()
    if event_key not in SIMULATED_EVENTS:
        logger.error(f"Unknown simulation event '{event_name}'. Available: {list(SIMULATED_EVENTS.keys())}")
        return None

    # Get fresh event instance with current timestamp
    template = SIMULATED_EVENTS[event_key]
    sim_event = SecurityEvent.from_dict(template.to_dict())

    logger.info(f"Injecting simulated security event: {sim_event.event}")
    event_bus.publish(sim_event)
    return sim_event
