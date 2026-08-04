"""
File Integrity Monitor (FIM) for Embedded Runtime Security Monitor (ERSM).
Computes SHA-256 hashes, compares against persistent baselines, and detects rapid mass modification bursts.
"""

import hashlib
import json
import os
import time
from typing import Dict, Any, List, Optional
from core.event import SecurityEvent, EventCategory, EventSeverity, EventConfidence
from monitors.base_monitor import BaseMonitor


class FileIntegrityMonitor(BaseMonitor):
    """
    Monitors target files/directories using SHA-256 hashes against a trusted baseline database.
    """

    def __init__(self, event_bus, platform_adapter, config: Dict[str, Any] = None):
        super().__init__("FileIntegrityMonitor", event_bus, platform_adapter, config)
        self.monitored_paths = self.config.get("monitored_paths", ["config"])
        self.baseline_path = self.config.get("baseline_path", "storage/fim_baseline.json")
        self.rapid_modification_threshold = self.config.get("rapid_modification_threshold", 30)
        self.rapid_window_seconds = self.config.get("rapid_modification_window_seconds", 10)

        self._modification_history: List[float] = []
        self._last_mass_alert_time = 0.0

    def compute_sha256(self, filepath: str) -> Optional[str]:
        """Calculates SHA-256 hash of a file."""
        if not os.path.isfile(filepath):
            return None
        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def get_file_metadata(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Returns file metadata: sha256, size, mtime, permissions."""
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None
        try:
            stat = os.stat(filepath)
            sha256_hash = self.compute_sha256(filepath)
            return {
                "sha256": sha256_hash,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "mode": oct(stat.st_mode)
            }
        except Exception:
            return None

    def scan_monitored_targets(self) -> Dict[str, Dict[str, Any]]:
        """Scans all configured monitored files/directories."""
        current_state: Dict[str, Dict[str, Any]] = {}
        for path in self.monitored_paths:
            abs_path = os.path.abspath(path)
            if os.path.isfile(abs_path):
                meta = self.get_file_metadata(abs_path)
                if meta:
                    current_state[abs_path] = meta
            elif os.path.isdir(abs_path):
                for root, _, files in os.walk(abs_path):
                    for file in files:
                        full_p = os.path.join(root, file)
                        meta = self.get_file_metadata(full_p)
                        if meta:
                            current_state[full_p] = meta
        return current_state

    def create_baseline(self) -> int:
        """Generates and saves current state as trusted baseline."""
        os.makedirs(os.path.dirname(os.path.abspath(self.baseline_path)), exist_ok=True)
        state = self.scan_monitored_targets()
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dumps(state, indent=2)
            json.dump(state, f, indent=2)
        self.logger.info(f"Created FIM baseline with {len(state)} files stored in {self.baseline_path}.")
        return len(state)

    def load_baseline(self) -> Dict[str, Dict[str, Any]]:
        """Loads trusted baseline from disk."""
        if not os.path.exists(self.baseline_path):
            return {}
        try:
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading FIM baseline from {self.baseline_path}: {e}")
            return {}

    def _check(self) -> None:
        baseline = self.load_baseline()
        if not baseline:
            # Auto-create baseline if none exists
            self.create_baseline()
            return

        current_state = self.scan_monitored_targets()
        now = time.time()
        modifications_count = 0

        # Check for modifications & deletions
        for path, old_meta in baseline.items():
            if path not in current_state:
                event = SecurityEvent(
                    category=EventCategory.INTEGRITY.value,
                    event="FILE_DELETED",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=30,
                    message=f"Monitored file deleted: {path}",
                    metadata={"path": path}
                )
                self.publish_event(event)
                modifications_count += 1
            else:
                new_meta = current_state[path]
                if old_meta.get("sha256") != new_meta.get("sha256"):
                    event = SecurityEvent(
                        category=EventCategory.INTEGRITY.value,
                        event="FILE_INTEGRITY_CHANGE",
                        severity=EventSeverity.HIGH.value,
                        confidence=EventConfidence.HIGH.value,
                        risk=30,
                        message=f"Monitored file modified: SHA-256 hash mismatch for {path}",
                        metadata={
                            "path": path,
                            "old_hash": old_meta.get("sha256"),
                            "new_hash": new_meta.get("sha256")
                        }
                    )
                    self.publish_event(event)
                    modifications_count += 1

        # Check for newly created files in monitored dirs
        for path in current_state:
            if path not in baseline:
                event = SecurityEvent(
                    category=EventCategory.INTEGRITY.value,
                    event="FILE_CREATED",
                    severity=EventSeverity.LOW.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=5,
                    message=f"New file created in monitored path: {path}",
                    metadata={"path": path}
                )
                self.publish_event(event)
                modifications_count += 1

        # Rapid File Modification Detection (Mass File Change)
        if modifications_count > 0:
            for _ in range(modifications_count):
                self._modification_history.append(now)

        cutoff = now - self.rapid_window_seconds
        self._modification_history = [ts for ts in self._modification_history if ts >= cutoff]

        if len(self._modification_history) >= self.rapid_modification_threshold:
            if (now - self._last_mass_alert_time) >= self.rapid_window_seconds:
                event = SecurityEvent(
                    category=EventCategory.INTEGRITY.value,
                    event="MASS_FILE_CHANGE",
                    severity=EventSeverity.HIGH.value,
                    confidence=EventConfidence.HIGH.value,
                    risk=30,
                    message=f"Rapid File Modification Burst: {len(self._modification_history)} files changed within {self.rapid_window_seconds}s.",
                    metadata={"modifications_count": len(self._modification_history)}
                )
                self.publish_event(event)
                self._last_mass_alert_time = now
