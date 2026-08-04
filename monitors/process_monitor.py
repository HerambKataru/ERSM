"""
Process Security & Behavior Monitor for Embedded Runtime Security Monitor (ERSM).
Monitors per-process resource consumption, spawn bursts, process restart loops, unexpected child processes, and network connections.
"""

import time
from typing import Dict, Any, Set, Tuple, List
import psutil
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class ProcessMonitor(BaseMonitor):
    """
    Monitors process life-cycles, restart loops, high CPU/RAM per-process, unexpected child processes, and process network activity.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("ProcessMonitor", event_bus, platform_adapter, config)
        self.cpu_hog_threshold = self.config.get("cpu_hog_threshold", 90.0)
        self.mem_hog_threshold_mb = self.config.get("mem_hog_threshold_mb", 1024)
        self.spawn_burst_threshold = self.config.get("spawn_burst_threshold", 15)
        self.spawn_burst_window = self.config.get("spawn_burst_window_seconds", 5)
        self.restart_loop_threshold = self.config.get("restart_loop_threshold", 5)
        self.suspicious_child_parents = set(self.config.get("suspicious_parents", ["word.exe", "excel.exe", "apache2", "nginx", "httpd", "python"]))

        self._known_pids: Set[int] = set()
        self._spawn_history: List[float] = []
        self._recent_name_spawns: Dict[str, List[float]] = {}  # proc_name -> list of timestamps
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
                    module=self.name,
                    message=f"Process Spawn Burst: {len(self._spawn_history)} new processes created within {self.spawn_burst_window}s.",
                    metadata={"spawn_count": len(self._spawn_history), "window_seconds": self.spawn_burst_window}
                )
                self.publish_event(event)
                self._last_burst_alert_time = now

        # 2. Inspect New Processes for CPU/RAM Hogs, Restart Loops, Child Process Anomaly, and Network Activity
        for pid in list(new_pids):
            try:
                proc = psutil.Process(pid)
                pname = proc.name()
                cmdline = " ".join(proc.cmdline()) if proc.cmdline() else pname

                # Track Process Restart Loops (rapid re-execution of same executable name)
                if pname not in self._recent_name_spawns:
                    self._recent_name_spawns[pname] = []
                self._recent_name_spawns[pname].append(now)

                # Clean old restarts
                self._recent_name_spawns[pname] = [
                    ts for ts in self._recent_name_spawns[pname] if ts >= (now - 30)
                ]

                if len(self._recent_name_spawns[pname]) >= self.restart_loop_threshold:
                    event = SecurityEvent(
                        category=EventCategory.PROCESS.value,
                        event="PROCESS_RESTART_LOOP",
                        severity=EventSeverity.HIGH.value,
                        confidence=EventConfidence.HIGH.value,
                        risk=30,
                        module=self.name,
                        message=f"Process Restart Loop: Process '{pname}' restarted {len(self._recent_name_spawns[pname])} times in 30s.",
                        metadata={"process_name": pname, "restart_count": len(self._recent_name_spawns[pname])}
                    )
                    self.publish_event(event)
                    self._recent_name_spawns[pname] = []

                # Unexpected Child Process Detection
                try:
                    parent = proc.parent()
                    if parent and parent.name().lower() in self.suspicious_child_parents and pname.lower() in ["cmd.exe", "powershell.exe", "bash", "sh", "zsh"]:
                        event = SecurityEvent(
                            category=EventCategory.PROCESS.value,
                            event="PROCESS_NETWORK_ACTIVITY",
                            severity=EventSeverity.HIGH.value,
                            confidence=EventConfidence.HIGH.value,
                            risk=30,
                            module=self.name,
                            message=f"Unexpected Child Process Spawns Shell: Parent '{parent.name()}' spawned shell process '{pname}' (PID {pid}).",
                            metadata={"pid": pid, "process": pname, "parent_pid": parent.pid, "parent": parent.name()}
                        )
                        self.publish_event(event)
                except Exception:
                    pass

                # Per-process Memory Hog
                mem_mb = proc.memory_info().rss / (1024 * 1024)
                if mem_mb >= self.mem_hog_threshold_mb:
                    event = SecurityEvent(
                        category=EventCategory.PROCESS.value,
                        event="PROCESS_MEMORY_ANOMALY",
                        severity=EventSeverity.LOW.value,
                        confidence=EventConfidence.LOW.value,
                        risk=5,
                        module=self.name,
                        message=f"Process '{pname}' (PID {pid}) consumed high memory: {mem_mb:.1f} MB.",
                        metadata={"pid": pid, "name": pname, "memory_mb": mem_mb}
                    )
                    self.publish_event(event)

                # Per-process CPU Hog
                cpu_p = proc.cpu_percent(interval=None)
                if cpu_p >= self.cpu_hog_threshold:
                    event = SecurityEvent(
                        category=EventCategory.PROCESS.value,
                        event="PROCESS_CPU_ANOMALY",
                        severity=EventSeverity.LOW.value,
                        confidence=EventConfidence.LOW.value,
                        risk=5,
                        module=self.name,
                        message=f"Process '{pname}' (PID {pid}) consumed high CPU: {cpu_p:.1f}%.",
                        metadata={"pid": pid, "name": pname, "cpu_percent": cpu_p}
                    )
                    self.publish_event(event)

                # Process Network Activity
                conns = proc.connections(kind="inet")
                if conns:
                    for c in conns:
                        if c.raddr:
                            event = SecurityEvent(
                                category=EventCategory.PROCESS.value,
                                event="PROCESS_NETWORK_ACTIVITY",
                                severity=EventSeverity.MEDIUM.value,
                                confidence=EventConfidence.MEDIUM.value,
                                risk=15,
                                module=self.name,
                                message=f"Suspicious Process Network Connection: '{pname}' (PID {pid}) connected to {c.raddr.ip}:{c.raddr.port}",
                                metadata={"pid": pid, "process": pname, "remote_ip": c.raddr.ip, "remote_port": c.raddr.port}
                            )
                            self.publish_event(event)
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
