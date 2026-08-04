"""
Simulation Engine for Embedded Runtime Security Monitor (ERSM).
Safely generates mock standardized security events for testing detection rules, risk engine, database, and transports.
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
        module="AuthMonitor",
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
        module="GatewayMonitor",
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
        module="NetworkMonitor",
        message="[SIMULATED] Rapid port scan pattern detected from 192.168.1.150 across 25 destination ports.",
        source="SIMULATOR",
        metadata={"simulated": True, "source_ip": "192.168.1.150", "ports_scanned": 25}
    ),
    "DNS_ATTACK": SecurityEvent(
        category=EventCategory.DNS.value,
        event="DNS_SERVER_CHANGED",
        severity=EventSeverity.HIGH.value,
        confidence=EventConfidence.HIGH.value,
        risk=30,
        module="DnsMonitor",
        message="[SIMULATED] DNS Hijack Suspected: System DNS server altered to rogue IP 185.220.101.5.",
        source="SIMULATOR",
        metadata={"simulated": True, "old_dns": ["8.8.8.8"], "new_dns": ["185.220.101.5"]}
    ),
    "USB_CONNECTED": SecurityEvent(
        category=EventCategory.USB.value,
        event="USB_CONNECTED",
        severity=EventSeverity.LOW.value,
        confidence=EventConfidence.HIGH.value,
        risk=5,
        module="UsbMonitor",
        message="[SIMULATED] External USB Flash Drive connected to host machine.",
        source="SIMULATOR",
        metadata={"simulated": True, "device_name": "SanDisk Ultra USB 3.0", "vendor": "SanDisk"}
    ),
    "UNKNOWN_USB_DEVICE": SecurityEvent(
        category=EventCategory.USB.value,
        event="UNKNOWN_USB_DEVICE",
        severity=EventSeverity.MEDIUM.value,
        confidence=EventConfidence.HIGH.value,
        risk=15,
        module="UsbMonitor",
        message="[SIMULATED] Unknown/Untrusted USB device connected: Vendor ID 0x1337, Product ID 0x0001.",
        source="SIMULATOR",
        metadata={"simulated": True, "device_name": "Unknown Keylogger", "vendor": "RogueVendor"}
    ),
    "USB_MALWARE_ALERT": SecurityEvent(
        category=EventCategory.USB.value,
        event="USB_MALWARE_ALERT",
        severity=EventSeverity.CRITICAL.value,
        confidence=EventConfidence.HIGH.value,
        risk=50,
        module="UsbMonitor",
        message="[SIMULATED] Antivirus reported Trojan executable originating from USB volume /Volumes/USB_STICK/autorun.exe.",
        source="REPORTED_BY_EXTERNAL_SECURITY_TOOL",
        metadata={"simulated": True, "threat_name": "Trojan.Win32.Autorun", "device_path": "/Volumes/USB_STICK"}
    ),
    "NEW_NETWORK_DEVICE": SecurityEvent(
        category=EventCategory.DEVICE.value,
        event="NEW_NETWORK_DEVICE",
        severity=EventSeverity.LOW.value,
        confidence=EventConfidence.HIGH.value,
        risk=5,
        module="NetworkDeviceMonitor",
        message="[SIMULATED] New rogue host discovered on local subnet: IP 192.168.1.205 (MAC: de:ad:be:ef:00:01).",
        source="SIMULATOR",
        metadata={"simulated": True, "ip": "192.168.1.205", "mac": "de:ad:be:ef:00:01"}
    ),
    "CPU_RESOURCE_ALERT": SecurityEvent(
        category=EventCategory.RESOURCE.value,
        event="CPU_RESOURCE_ALERT",
        severity=EventSeverity.MEDIUM.value,
        confidence=EventConfidence.MEDIUM.value,
        risk=15,
        module="SystemMonitor",
        message="[SIMULATED] Sustained abnormal CPU utilization: 98.2% for 45 seconds.",
        source="SIMULATOR",
        metadata={"simulated": True, "cpu_percent": 98.2, "duration_seconds": 45}
    ),
    "FILE_PERMISSION_CHANGED": SecurityEvent(
        category=EventCategory.FILE_ACTIVITY.value,
        event="FILE_PERMISSION_CHANGED",
        severity=EventSeverity.MEDIUM.value,
        confidence=EventConfidence.HIGH.value,
        risk=15,
        module="FileIntegrityMonitor",
        message="[SIMULATED] File permissions modified for sensitive configuration file /etc/shadow.",
        source="SIMULATOR",
        metadata={"simulated": True, "path": "/etc/shadow", "old_mode": "0600", "new_mode": "0777"}
    ),
    "MASS_FILE_CHANGE": SecurityEvent(
        category=EventCategory.FILE_ACTIVITY.value,
        event="MASS_FILE_CHANGE",
        severity=EventSeverity.HIGH.value,
        confidence=EventConfidence.HIGH.value,
        risk=30,
        module="FileIntegrityMonitor",
        message="[SIMULATED] Rapid mass file modification burst: 45 files changed within 5 seconds (Ransomware Indicator).",
        source="SIMULATOR",
        metadata={"simulated": True, "modifications_count": 45}
    ),
    "PROCESS_RESTART_LOOP": SecurityEvent(
        category=EventCategory.PROCESS.value,
        event="PROCESS_RESTART_LOOP",
        severity=EventSeverity.HIGH.value,
        confidence=EventConfidence.HIGH.value,
        risk=30,
        module="ProcessMonitor",
        message="[SIMULATED] Process crash/restart loop detected: 'malware_loader' restarted 10 times in 15 seconds.",
        source="SIMULATOR",
        metadata={"simulated": True, "process_name": "malware_loader", "restart_count": 10}
    ),
    "FIREWALL_DISABLED": SecurityEvent(
        category=EventCategory.FIREWALL.value,
        event="FIREWALL_DISABLED",
        severity=EventSeverity.CRITICAL.value,
        confidence=EventConfidence.HIGH.value,
        risk=50,
        module="FirewallMonitor",
        message="[SIMULATED] Host Application Firewall has been turned OFF by external process.",
        source="SIMULATOR",
        metadata={"simulated": True, "firewall_status": "DISABLED"}
    )
}


def trigger_simulation_event(event_name: str, event_bus: EventBus) -> Optional[SecurityEvent]:
    """
    Generates and dispatches a simulated security event cleanly through the ERSM pipeline.
    """
    event_key = event_name.upper()
    if event_key not in SIMULATED_EVENTS:
        logger.error(f"Unknown simulation event '{event_name}'. Available: {list(SIMULATED_EVENTS.keys())}")
        return None

    # Instantiate fresh event with current timestamp
    template = SIMULATED_EVENTS[event_key]
    sim_event = SecurityEvent.from_dict(template.to_dict())

    logger.info(f"Injecting simulated security event: {sim_event.event} ({sim_event.category})")
    event_bus.publish(sim_event)
    return sim_event
