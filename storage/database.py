"""
SQLite Event Database Manager for Embedded Runtime Security Monitor (ERSM).
Provides persistent relational storage and query helper functions for security events.
"""

import json
import os
import sqlite3
import threading
from typing import Dict, List, Any, Optional
from core.event import SecurityEvent
from utils.logger import setup_logger

logger = setup_logger("ERSM.Database")


class DatabaseManager:
    """
    SQLite database interface for storing and querying standardized SecurityEvent records.
    """

    def __init__(self, db_path: str = "storage/ersm.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes tables and indexes."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT NOT NULL,
                            host TEXT NOT NULL,
                            platform TEXT NOT NULL,
                            module TEXT NOT NULL DEFAULT 'General',
                            category TEXT NOT NULL,
                            event TEXT NOT NULL,
                            severity TEXT NOT NULL,
                            confidence TEXT NOT NULL,
                            risk INTEGER NOT NULL,
                            source TEXT NOT NULL,
                            message TEXT NOT NULL,
                            metadata TEXT NOT NULL
                        )
                    """)
                    # Check if module column exists in case existing database file was created earlier
                    cursor = conn.execute("PRAGMA table_info(events)")
                    columns = [row[1] for row in cursor.fetchall()]
                    if "module" not in columns:
                        conn.execute("ALTER TABLE events ADD COLUMN module TEXT NOT NULL DEFAULT 'General'")

                    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON events(timestamp)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_cat ON events(category)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_sev ON events(severity)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_risk ON events(risk)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_mod ON events(module)")
            finally:
                conn.close()

    def save_event(self, event: SecurityEvent) -> int:
        """Saves a SecurityEvent object into SQLite database."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    cursor = conn.execute("""
                        INSERT INTO events (
                            timestamp, host, platform, module, category, event, severity,
                            confidence, risk, source, message, metadata
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.timestamp,
                        event.host,
                        event.platform,
                        getattr(event, "module", "General"),
                        event.category,
                        event.event,
                        event.severity,
                        event.confidence,
                        event.risk,
                        event.source,
                        event.message,
                        json.dumps(event.metadata)
                    ))
                    return cursor.lastrowid
            except Exception as e:
                logger.error(f"Failed to insert event into SQLite: {e}")
                return -1
            finally:
                conn.close()

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Queries recent security events ordered by ID descending."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute(
                    "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
                )
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_events_by_severity(self, severity: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Queries security events filtered by severity."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute(
                    "SELECT * FROM events WHERE severity = ? ORDER BY id DESC LIMIT ?",
                    (severity.upper(), limit)
                )
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_events_by_category(self, category: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Queries security events filtered by category."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute(
                    "SELECT * FROM events WHERE category = ? ORDER BY id DESC LIMIT ?",
                    (category.upper(), limit)
                )
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_highest_risk_events(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Queries highest risk score events."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute(
                    "SELECT * FROM events ORDER BY risk DESC, id DESC LIMIT ?", (limit,)
                )
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_daily_counts(self) -> List[Dict[str, Any]]:
        """Calculates event counts per day."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute("""
                    SELECT substr(timestamp, 1, 10) AS date, COUNT(*) AS count
                    FROM events
                    GROUP BY substr(timestamp, 1, 10)
                    ORDER BY date DESC
                """)
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_events_by_day(self) -> List[Dict[str, Any]]:
        """Queries event counts grouped by day."""
        return self.get_daily_counts()

