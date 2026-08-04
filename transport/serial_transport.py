"""
USB Serial Transport interface for streaming security status and events to ESP32 hardware device.
"""

import json
import logging
import threading
import time
from typing import Dict, Any
from core.event import SecurityEvent
from transport.base_transport import BaseTransport
from utils.logger import setup_logger

logger = setup_logger("ERSM.SerialTransport")

try:
    import serial
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False


class SerialTransport(BaseTransport):
    """
    Manages USB Serial connection to ESP32 hardware security monitor unit.
    Format: Structured JSON frame terminated by newline.
    """

    def __init__(self, port: str = "/dev/tty.usbmodem14101", baudrate: int = 115200, enabled: bool = False):
        self.port = port
        self.baudrate = baudrate
        self.enabled = enabled
        self._serial_conn = None
        self._lock = threading.Lock()

        if self.enabled:
            self._connect()

    def _connect(self) -> bool:
        """Attempts connection to USB serial port."""
        if not SERIAL_AVAILABLE:
            logger.warning("pyserial module not installed. Serial transport running in simulated/dry-run mode.")
            return False

        with self._lock:
            try:
                self._serial_conn = serial.Serial(self.port, self.baudrate, timeout=1)
                logger.info(f"Connected to ESP32 hardware on USB Serial port {self.port} @ {self.baudrate} baud.")
                return True
            except Exception as e:
                logger.warning(f"Could not open USB Serial port {self.port}: {e}. (Will retry when device connects)")
                self._serial_conn = None
                return False

    def send_event(self, event: SecurityEvent) -> None:
        """Transmits a security event packet to ESP32 over serial."""
        if not self.enabled:
            return

        payload = {
            "type": "EVENT",
            "data": event.to_dict()
        }
        self._write_payload(payload)

    def send_status(self, status: Dict[str, Any]) -> None:
        """Transmits global status summary frame to ESP32 for OLED/LED updates."""
        if not self.enabled:
            return

        payload = {
            "type": "STATUS",
            "data": status
        }
        self._write_payload(payload)

    def _write_payload(self, payload: Dict[str, Any]) -> None:
        with self._lock:
            msg = json.dumps(payload) + "\n"
            if self._serial_conn and self._serial_conn.is_open:
                try:
                    self._serial_conn.write(msg.encode("utf-8"))
                    self._serial_conn.flush()
                except Exception as e:
                    logger.error(f"Error sending payload to ESP32 over Serial: {e}")
                    self._serial_conn = None
            else:
                # Debug logging in dry-run mode
                logger.debug(f"[ESP32 Serial Transport Simulated] TX: {msg.strip()}")
