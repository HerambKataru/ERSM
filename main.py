#!/usr/bin/env python3
"""
Embedded Runtime Security Monitor (ERSM) - Host Agent
Main entry point for B.Tech CSE Capstone Project.
"""

import argparse
import json
import os
import signal
import sys
import time
from typing import Dict, Any, List

# Add workspace directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.event import SecurityEvent, EventCategory, EventSeverity
from core.event_bus import EventBus
from core.risk_engine import RiskEngine
from core.correlation_engine import CorrelationEngine
from core.state_manager import StateManager
from platform import get_platform_adapter
from storage.database import DatabaseManager
from transport.console import ConsoleTransport
from transport.json_logger import JSONLogTransport
from transport.serial_transport import SerialTransport
from monitors.system_monitor import SystemMonitor
from monitors.auth_monitor import AuthMonitor
from monitors.network_monitor import NetworkMonitor
from monitors.arp_monitor import ArpMonitor
from monitors.process_monitor import ProcessMonitor
from monitors.file_integrity_monitor import FileIntegrityMonitor
from monitors.persistence_monitor import PersistenceMonitor
from monitors.dns_monitor import DnsMonitor
from monitors.usb_monitor import UsbMonitor
from monitors.external_security_monitor import ExternalSecurityMonitor
from monitors.firewall_monitor import FirewallMonitor
from monitors.gateway_monitor import GatewayMonitor
from monitors.network_device_monitor import NetworkDeviceMonitor
from utils.logger import setup_logger
from utils.simulation import trigger_simulation_event, SIMULATED_EVENTS

logger = setup_logger("ERSM.Main")


class ERSMAgent:
    """
    Core orchestrator for ERSM Host Agent.
    Wires monitors, event bus, engines, storage, and transports.
    """

    def __init__(self, config_path: str = "config/config.json"):
        self.config_path = config_path
        self.config = self._load_config(config_path)

        # 1. Platform Adapter Auto-detection
        self.platform_adapter = get_platform_adapter()
        logger.info(f"Initialized Platform Adapter: {self.platform_adapter.get_platform_name()}")

        # 2. Event Bus & Core Engines
        self.event_bus = EventBus()
        self.risk_engine = RiskEngine(self.config.get("risk_engine", {}))
        self.correlation_engine = CorrelationEngine(
            event_bus=self.event_bus,
            window_seconds=self.config.get("correlation_engine", {}).get("time_window_seconds", 60),
            config=self.config.get("correlation_engine", {})
        )
        self.state_manager = StateManager()
        self.db = DatabaseManager(self.config.get("storage", {}).get("db_path", "storage/ersm.db"))

        # 3. Transports
        transport_cfg = self.config.get("transport", {})
        self.console_transport = ConsoleTransport(
            enable_colors=transport_cfg.get("console", {}).get("enabled", True)
        )
        self.json_transport = JSONLogTransport(
            file_path=self.config.get("storage", {}).get("json_log_path", "logs/events.jsonl")
        )
        self.serial_transport = SerialTransport(
            port=transport_cfg.get("serial", {}).get("port", "/dev/tty.usbmodem14101"),
            baudrate=transport_cfg.get("serial", {}).get("baudrate", 115200),
            enabled=transport_cfg.get("serial", {}).get("enabled", False)
        )

        # 4. Monitors
        monitors_cfg = self.config.get("monitors", {})
        self.monitors = [
            SystemMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("system", {})),
            AuthMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("auth", {})),
            NetworkMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("network", {})),
            ArpMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("arp", {})),
            ProcessMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("process", {})),
            FileIntegrityMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("file_integrity", {})),
            PersistenceMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("persistence", {})),
            DnsMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("dns", {})),
            UsbMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("usb", {})),
            ExternalSecurityMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("external_security", {})),
            FirewallMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("firewall", {})),
            GatewayMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("gateway", {})),
            NetworkDeviceMonitor(self.event_bus, self.platform_adapter, monitors_cfg.get("network_device", {}))
        ]

        # 5. Wire Event Bus Pipeline
        self.event_bus.subscribe(self._on_event_published)
        self._running = False

    def _load_config(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            logger.warning(f"Configuration file {path} not found. Using default settings.")
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading configuration file {path}: {e}")
            return {}

    def _on_event_published(self, event: SecurityEvent) -> None:
        """
        Main pipeline callback executed on every security event.
        Calculates risk, triggers correlation, updates state, stores, and sends to transports.
        """
        # Risk Evaluation
        new_risk = self.risk_engine.process_event(event)
        status_label = self.risk_engine.status_label

        # State Manager Update
        self.state_manager.update_risk(new_risk, status_label)
        self.state_manager.record_event(event)

        # Database Storage (SQLite)
        self.db.save_event(event)

        # Transports Output
        self.json_transport.send_event(event)
        self.serial_transport.send_event(event)
        self.console_transport.send_event(event)

        # Correlation Engine Evaluation
        self.correlation_engine.process_event(event)

    def start(self) -> None:
        """Starts the ERSM Agent background monitors and daemon loop."""
        self._running = True
        logger.info("Starting ERSM Host Agent monitoring engines...")

        # Record Agent Startup Event
        startup_event = SecurityEvent(
            category=EventCategory.SYSTEM.value,
            event="AGENT_STARTED",
            severity=EventSeverity.INFO.value,
            message=f"ERSM Host Agent started successfully on platform {self.platform_adapter.get_platform_name()}.",
            risk=0,
            module="AgentEngine"
        )
        self.event_bus.publish(startup_event)

        # Start background monitor threads
        for monitor in self.monitors:
            monitor.start()

        # Terminal UI Dashboard loop
        dashboard_interval = self.config.get("transport", {}).get("console", {}).get("banner_refresh_seconds", 2)
        last_dashboard_time = 0.0

        try:
            while self._running:
                now = time.time()
                # Update telemetry status
                self.state_manager.update_telemetry()
                status_summary = self.state_manager.get_status_summary()

                # Stream periodic status packet to ESP32 over serial
                self.serial_transport.send_status(status_summary)

                # Render dashboard
                if (now - last_dashboard_time) >= dashboard_interval:
                    self.console_transport.render_dashboard(
                        status_summary,
                        self.state_manager.recent_events
                    )
                    last_dashboard_time = now

                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Received shutdown signal.")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stops monitors and cleans up resources."""
        if not self._running:
            return
        self._running = False
        logger.info("Stopping ERSM Host Agent...")

        for monitor in self.monitors:
            monitor.stop()

        stopping_event = SecurityEvent(
            category=EventCategory.SYSTEM.value,
            event="AGENT_STOPPING",
            severity=EventSeverity.INFO.value,
            message="ERSM Host Agent background process stopping.",
            risk=0,
            module="AgentEngine"
        )
        self.event_bus.publish(stopping_event)
        logger.info("ERSM Host Agent shutdown complete.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Embedded Runtime Security Monitor (ERSM) - Host Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py                             # Run ERSM Host Agent continuous daemon
  python3 main.py --simulate AUTH_FAILURE     # Inject simulated AUTH_FAILURE event
  python3 main.py --simulate-all              # Inject all simulation events sequentially
  python3 main.py --fim-init                  # Create baseline SHA-256 for file integrity monitor
  python3 main.py --query-recent 10           # Query last 10 SQLite security events
  python3 main.py --query-category NETWORK    # Query events by category
  python3 main.py --query-daily               # Query event counts by day
        """
    )
    parser.add_argument("--config", default="config/config.json", help="Path to config.json file")
    parser.add_argument("--simulate", choices=list(SIMULATED_EVENTS.keys()), help="Simulate a specific security event")
    parser.add_argument("--simulate-all", action="store_true", help="Simulate all available security events")
    parser.add_argument("--fim-init", action="store_true", help="Initialize File Integrity Monitor SHA-256 baseline")
    parser.add_argument("--fim-verify", action="store_true", help="Verify File Integrity Monitor targets against baseline")
    parser.add_argument("--query-recent", type=int, help="Query N recent security events from SQLite database")
    parser.add_argument("--query-high-risk", action="store_true", help="Query highest risk events from SQLite database")
    parser.add_argument("--query-category", help="Query events filtered by category (e.g. NETWORK, USB, FIREWALL)")
    parser.add_argument("--query-daily", action="store_true", help="Query daily aggregated security event counts")
    return parser.parse_args()


def main():
    args = parse_args()

    # Query CLI mode
    if args.query_recent or args.query_high_risk or args.query_category or args.query_daily:
        db = DatabaseManager("storage/ersm.db")
        if args.query_high_risk:
            print("\n=== HIGHEST RISK SECURITY EVENTS ===")
            events = db.get_highest_risk_events(limit=10)
            for ev in events:
                print(f"[{ev['timestamp']}] [{ev['severity']}] (Risk {ev['risk']}) {ev['event']}: {ev['message']}")
            print(f"\nTotal records returned: {len(events)}\n")
        elif args.query_category:
            print(f"\n=== SECURITY EVENTS FOR CATEGORY: {args.query_category.upper()} ===")
            events = db.get_events_by_category(args.query_category, limit=50)
            for ev in events:
                print(f"[{ev['timestamp']}] [{ev['severity']}] (Risk {ev['risk']}) {ev['event']}: {ev['message']}")
            print(f"\nTotal records returned: {len(events)}\n")
        elif args.query_daily:
            print("\n=== DAILY AGGREGATED SECURITY EVENT COUNTS ===")
            counts = db.get_daily_counts()
            for row in counts:
                print(f"Date: {row['date']} | Total Events: {row['count']}")
            print(f"\nTotal days recorded: {len(counts)}\n")
        else:
            print(f"\n=== RECENT {args.query_recent} SECURITY EVENTS ===")
            events = db.get_recent_events(limit=args.query_recent)
            for ev in events:
                print(f"[{ev['timestamp']}] [{ev['severity']}] (Risk {ev['risk']}) {ev['event']}: {ev['message']}")
            print(f"\nTotal records returned: {len(events)}\n")
        return

    # FIM Init mode
    if args.fim_init:
        adapter = get_platform_adapter()
        bus = EventBus()
        fim = FileIntegrityMonitor(bus, adapter, {"monitored_paths": ["config"], "baseline_path": "storage/fim_baseline.json"})
        count = fim.create_baseline()
        print(f"Success: File Integrity Monitor initialized baseline with {count} files stored in storage/fim_baseline.json.")
        return

    agent = ERSMAgent(config_path=args.config)

    # Simulation CLI mode
    if args.simulate:
        print(f"\n=== SIMULATION MODE: Injecting {args.simulate} ===")
        trigger_simulation_event(args.simulate, agent.event_bus)
        time.sleep(1)
        print("\nSimulation complete. Event written to SQLite database and logs/events.jsonl.\n")
        return

    if args.simulate_all:
        print("\n=== SIMULATION MODE: Injecting all mock security events ===")
        for event_name in SIMULATED_EVENTS:
            trigger_simulation_event(event_name, agent.event_bus)
            time.sleep(0.5)
        print("\nSimulation complete. All events processed through risk & correlation engines.\n")
        return

    # Signal handlers for clean termination
    def handle_signal(sig, frame):
        logger.info("Signal received. Terminating agent...")
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Run agent
    agent.start()


if __name__ == "__main__":
    main()
