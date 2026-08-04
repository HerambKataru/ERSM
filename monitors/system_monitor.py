"""
System Resource Security Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors host CPU, RAM, Disk utilization, and total process count against configurable threshold limits.
"""

import time
from typing import Dict, Any
import psutil
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class SystemMonitor(BaseMonitor):
    """
    Monitors host system resources and process capacity limits.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("SystemMonitor", event_bus, platform_adapter, config)
        self.cpu_threshold = self.config.get("cpu_threshold_percent", 90.0)
        self.cpu_duration_seconds = self.config.get("cpu_duration_seconds", 30)
        self.ram_threshold = self.config.get("ram_threshold_percent", 90.0)
        self.ram_duration_seconds = self.config.get("ram_duration_seconds", 30)
        self.disk_threshold = self.config.get("disk_threshold_percent", 95.0)
        self.process_count_threshold = self.config.get("process_count_threshold", 400)

        self._high_cpu_start_time: float = 0.0
        self._high_ram_start_time: float = 0.0
        self._cpu_anomaly_emitted = False
        self._ram_anomaly_emitted = False
        self._disk_warning_emitted = False
        self._process_count_emitted = False

    def _check(self) -> None:
        now = time.time()
        cpu_percent = psutil.cpu_percent(interval=None)
        ram_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage("/").percent
        proc_count = len(psutil.pids())

        # 1. CPU Duration Anomaly (CPU_RESOURCE_ALERT)
        if cpu_percent >= self.cpu_threshold:
            if self._high_cpu_start_time == 0.0:
                self._high_cpu_start_time = now
            elif (now - self._high_cpu_start_time) >= self.cpu_duration_seconds:
                if not self._cpu_anomaly_emitted:
                    duration_secs = int(now - self._high_cpu_start_time)
                    event = SecurityEvent(
                        category=EventCategory.RESOURCE.value,
                        event="CPU_RESOURCE_ALERT",
                        severity=EventSeverity.MEDIUM.value,
                        confidence=EventConfidence.MEDIUM.value,
                        risk=15,
                        module=self.name,
                        message=f"Sustained High CPU Usage Alert: {cpu_percent:.1f}% for over {duration_secs}s.",
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

        # 2. RAM Duration Anomaly (MEMORY_RESOURCE_ALERT)
        if ram_percent >= self.ram_threshold:
            if self._high_ram_start_time == 0.0:
                self._high_ram_start_time = now
            elif (now - self._high_ram_start_time) >= self.ram_duration_seconds:
                if not self._ram_anomaly_emitted:
                    duration_secs = int(now - self._high_ram_start_time)
                    event = SecurityEvent(
                        category=EventCategory.RESOURCE.value,
                        event="MEMORY_RESOURCE_ALERT",
                        severity=EventSeverity.MEDIUM.value,
                        confidence=EventConfidence.MEDIUM.value,
                        risk=15,
                        module=self.name,
                        message=f"Sustained High RAM Usage Alert: {ram_percent:.1f}% for over {duration_secs}s.",
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

        # 3. Disk Usage Warning (DISK_RESOURCE_ALERT)
        if disk_percent >= self.disk_threshold:
            if not self._disk_warning_emitted:
                event = SecurityEvent(
                    category=EventCategory.RESOURCE.value,
                    event="DISK_RESOURCE_ALERT",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=30,
                    module=self.name,
                    message=f"Critical Disk Resource Alert: Disk utilization at {disk_percent:.1f}% capacity.",
                    metadata={"disk_percent": disk_percent, "threshold": self.disk_threshold}
                )
                self.publish_event(event)
                self._disk_warning_emitted = True
        else:
            self._disk_warning_emitted = False

        # 4. Total Process Count Alert (PROCESS_COUNT_ALERT)
        if proc_count >= self.process_count_threshold:
            if not self._process_count_emitted:
                event = SecurityEvent(
                    category=EventCategory.RESOURCE.value,
                    event="PROCESS_COUNT_ALERT",
                    severity=EventSeverity.MEDIUM.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=15,
                    module=self.name,
                    message=f"High Process Count Alert: Total active process count reached {proc_count}.",
                    metadata={"process_count": proc_count, "threshold": self.process_count_threshold}
                )
                self.publish_event(event)
                self._process_count_emitted = True
        else:
            self._process_count_emitted = False
