"""
JSON Lines (JSONL) file logger transport for ERSM Host Agent.
"""

import json
import os
import threading
from typing import Dict, Any
from core.event import SecurityEvent
from transport.base_transport import BaseTransport
from utils.logger import setup_logger

logger = setup_logger("ERSM.JSONLogger")


class JSONLogTransport(BaseTransport):
    """
    Appends standardized SecurityEvent records as JSON objects to a .jsonl file.
    """

    def __init__(self, file_path: str = "logs/events.jsonl"):
        self.file_path = file_path
        os.makedirs(os.path.dirname(os.path.abspath(self.file_path)), exist_ok=True)
        self._lock = threading.Lock()

    def send_event(self, event: SecurityEvent) -> None:
        """Appends event JSON string to .jsonl file."""
        with self._lock:
            try:
                with open(self.file_path, "a", encoding="utf-8") as f:
                    f.write(event.to_json() + "\n")
                    f.flush()
            except Exception as e:
                logger.error(f"Failed writing security event to {self.file_path}: {e}")
