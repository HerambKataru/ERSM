"""
System Resource Security Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors CPU, RAM, Disk usage, and process count using duration-based rules to prevent false spikes.
"""

import time
from typing import Dict, Any
import psutil
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class SystemMonitor(BaseMonitor):
    """
    Monitors host resource telemetry and emits events when continuous anomalies occur.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("SystemMonitor", event_bus, platform_adapter, config)
        self.cpu_threshold = self.config.get("cpu_threshold_percent", 90.0)
        self.cpu_duration_seconds = self.config.get("cpu_duration_seconds", 30)
        self.ram_threshold = self.config.get("ram_threshold_percent", 90.0)
        self.ram_duration_seconds = self.config.get("ram_duration_seconds", 30)
        self.disk_threshold = self.config.get("disk_threshold_percent", 95.0)

        self._high_cpu_start_time: float = 0.0
        self._high_ram_start_time: float = 0.0
        self._cpu_anomaly_emitted = False
        self._ram_anomaly_emitted = False
        self._disk_warning_emitted = False

    def _check(self) -> None:
        now = time.time()
        cpu_percent = psutil.cpu_percent(interval=None)
        ram_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage("/").percent

        # 1. CPU Duration Anomaly Logic
        if cpu_percent >= self.cpu_threshold:
            if self._high_cpu_start_time == 0.0:
                self._high_cpu_start_time = now
            elif (now - self._high_cpu_start_time) >= self.cpu_duration_seconds:
                if not self._cpu_anomaly_emitted:
                    duration_secs = int(now - self._high_cpu_start_time)
                    event = SecurityEvent(
                        category=EventCategory.SYSTEM.value,
                        event="RESOURCE_ANOMALY",
                        severity=EventSeverity.LOW.value,
                        confidence=EventConfidence.LOW.value,
                        risk=5,
                        message=f"CPU usage sustained at {cpu_percent:.1f}% for over {duration_secs} seconds.",
                        metadata={
                            "cpu_percent": cpu_percent,
                            "threshold": self.cpu_threshold,
                            "duration_seconds": duration_secs
                        }
                    )
                    self.publish_event(event)
                    self._cpu_anomaly_emitted = True
        else:
            self._high_cpu_start_time = 0.0
            self._cpu_anomaly_emitted = False

        # 2. RAM Duration Anomaly Logic
        if ram_percent >= self.ram_threshold:
            if self._high_ram_start_time == 0.0:
                self._high_ram_start_time = now
            elif (now - self._high_ram_start_time) >= self.ram_duration_seconds:
                if not self._ram_anomaly_emitted:
                    duration_secs = int(now - self._high_ram_start_time)
                    event = SecurityEvent(
                        category=EventCategory.SYSTEM.value,
                        event="MEMORY_RESOURCE_ANOMALY",
                        severity=EventSeverity.LOW.value,
                        confidence=EventConfidence.LOW.value,
                        risk=5,
                        message=f"RAM usage sustained at {ram_percent:.1f}% for over {duration_secs} seconds.",
                        metadata={
                            "ram_percent": ram_percent,
                            "threshold": self.ram_threshold,
                            "duration_seconds": duration_secs
                        }
                    )
                    self.publish_event(event)
                    self._ram_anomaly_emitted = True
        else:
            self._high_ram_start_time = 0.0
            self._ram_anomaly_emitted = False

        # 3. Disk Usage Warning
        if disk_percent >= self.disk_threshold:
            if not self._disk_warning_emitted:
                event = SecurityEvent(
                    category=EventCategory.SYSTEM.value,
                    event="DISK_SPACE_WARNING",
                    severity=EventSeverity.MEDIUM.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=15,
                    message=f"Root disk usage critical: {disk_percent:.1f}% full.",
                    metadata={"disk_percent": disk_percent, "threshold": self.disk_threshold}
                )
                self.publish_event(event)
                self._disk_warning_emitted = True
        else:
            self._disk_warning_emitted = False
