"""
Process Security Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors process creation/termination, spawn bursts, and abnormal per-process resource utilization.
"""

import time
from typing import Dict, Any, Set, Tuple, List
import psutil
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class ProcessMonitor(BaseMonitor):
    """
    Monitors process life-cycles, high CPU/RAM per-process consumption, and spawn bursts.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("ProcessMonitor", event_bus, platform_adapter, config)
        self.cpu_hog_threshold = self.config.get("cpu_hog_threshold", 90.0)
        self.mem_hog_threshold_mb = self.config.get("mem_hog_threshold_mb", 1024)
        self.spawn_burst_threshold = self.config.get("spawn_burst_threshold", 15)
        self.spawn_burst_window = self.config.get("spawn_burst_window_seconds", 5)

        self._known_pids: Set[int] = set()
        self._spawn_history: List[float] = []
        self._initialized = False
        self._last_burst_alert_time = 0.0

    def _check(self) -> None:
        now = time.time()
        current_pids = set(psutil.pids())

        if not self._initialized:
            self._known_pids = current_pids
            self._initialized = True
            return

        new_pids = current_pids - self._known_pids
        self._known_pids = current_pids

        # Track spawn history for burst detection
        for pid in new_pids:
            self._spawn_history.append(now)

        # Clean old spawn history
        cutoff = now - self.spawn_burst_window
        self._spawn_history = [ts for ts in self._spawn_history if ts >= cutoff]

        # 1. Process Spawn Burst Detection
        if len(self._spawn_history) >= self.spawn_burst_threshold:
            if (now - self._last_burst_alert_time) >= self.spawn_burst_window:
                event = SecurityEvent(
                    category=EventCategory.PROCESS.value,
                    event="PROCESS_SPAWN_BURST",
                    severity=EventSeverity.MEDIUM.value,
                    confidence=EventConfidence.MEDIUM.value,
                    risk=15,
                    message=f"Process Spawn Burst: {len(self._spawn_history)} new processes created within {self.spawn_burst_window}s.",
                    metadata={"spawn_count": len(self._spawn_history), "window_seconds": self.spawn_burst_window}
                )
                self.publish_event(event)
                self._last_burst_alert_time = now

        # 2. Per-Process Resource Hogging Inspection
        for pid in list(new_pids)[:10]:  # Inspect newly spawned processes
            try:
                proc = psutil.Process(pid)
                mem_mb = proc.memory_info().rss / (1024 * 1024)
                if mem_mb >= self.mem_hog_threshold_mb:
                    event = SecurityEvent(
                        category=EventCategory.PROCESS.value,
                        event="PROCESS_RESOURCE_ANOMALY",
                        severity=EventSeverity.LOW.value,
                        confidence=EventConfidence.LOW.value,
                        risk=5,
                        message=f"Process '{proc.name()}' (PID {pid}) consumed unusually high memory: {mem_mb:.1f} MB.",
                        metadata={"pid": pid, "name": proc.name(), "memory_mb": mem_mb}
                    )
                    self.publish_event(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
