# Embedded Runtime Security Monitor (ERSM)


> **Comprehensive End-to-End System Guide: Host Security Agent & ESP32 Hardware Console**

---

## 1. Executive Summary & Project Vision

The **Embedded Runtime Security Monitor (ERSM)** is an end-to-end, hardware-assisted runtime security monitoring system designed for modern operating systems (Windows, macOS, Linux). 

### The Problem
Traditional host-based security monitors and intrusion detection systems run entirely in software on the target OS. If malware achieves administrative/root privileges or executes ransomware payloads, it can quietly suppress local alert notifications, modify system logs, terminate monitoring processes, or obscure its activity from the user.

### The ERSM Solution
ERSM solves this single-point-of-failure through **Hardware-Assisted Security Monitoring**:
1. **Host Security Agent**: A modular, multi-threaded daemon running on the host system from boot until shutdown. It continuously gathers low-level OS telemetry across 14 security domains, normalizes indicators into standardized security events, calculates real-time risk scores with dynamic time decay, and correlates multi-layer threat patterns.
2. **Out-of-Band ESP32 Hardware Console**: A physically isolated hardware unit (ESP32 microcontroller with OLED display, RGB status LED, piezo siren, and physical mute button) connected via USB Serial UART. The ESP32 displays real-time risk status and triggers physical audible/visual alerts that **cannot be silenced or tampered with by malware on the host computer**.

```
+---------------------------------------------------------------------------------------------------+
|                                          ERSM HOST AGENT                                          |
|                                                                                                   |
|  +---------------------+   +-----------------------+   +---------------------------------------+  |
|  | System & Resource   |   | Auth & Process        |   | Network, Gateway, DNS, Port & FIM     |  |
|  | (CPU/RAM/Disk/Count)|   | (Log Streams/Restart) |   | (ARP/Subnet/Hashes/Firewall/USB)      |  |
|  +----------+----------+   +-----------+-----------+   +-------------------+-------------------+  |
|             |                          |                                   |                      |
|             +--------------------------+-----------------------------------+                      |
|                                        v                                                          |
|                          +---------------------------+                                            |
|                          |   Thread-Safe Event Bus   |                                            |
|                          +-------------+-------------+                                            |
|                                        v                                                          |
|             +--------------------------+-----------------------------------+                      |
|             v                          v                                   v                      |
|   +-------------------+     +--------------------+              +--------------------+            |
|   | Risk Engine       |     | Correlation Engine |              | SQLite & JSONL     |            |
|   | (Decay & Limits)  |     | (Multi-Event Rules)|              | Database Storage   |            |
|   +---------+---------+     +----------+---------+              +----------+---------+            |
|             |                          |                                   |                      |
|             +--------------------------+-----------------------------------+                      |
|                                        v                                                          |
|                          +---------------------------+                                            |
|                          | Global State Manager &    |                                            |
|                          | Transport Interface       |                                            |
|                          +-------------+-------------+                                            |
|                                        |                                                          |
+----------------------------------------|----------------------------------------------------------+
                                         v  (USB Serial Protocol / JSON Stream @ 115200 Baud)
                         +-------------------------------+
                         |  ESP32 Hardware Security Unit |
                         |  - FreeRTOS Dual-Core Task    |
                         |  - SSD1306 128x64 OLED Screen |
                         |  - RGB Tri-Color Status LED   |
                         |  - Active Siren Piezo Buzzer  |
                         |  - Physical ACK/Mute Button   |
                         +-------------------------------+
```

---

## 2. Comprehensive Directory & Repository Structure

```
ERSM/
├── main.py                          # Main entry point, daemon orchestrator, SQLite query CLI, & simulation runner
├── config/
│   └── config.json                  # Thresholds, intervals, whitelists, risk weights, correlation rules, & transport config
├── core/
│   ├── __init__.py
│   ├── event.py                     # Standardized SecurityEvent model (category, event, severity, risk, confidence, module)
│   ├── event_bus.py                 # Thread-safe publisher-subscriber Event Bus
│   ├── risk_engine.py               # Global risk scoring (0-100), dynamic time decay, rate-limiting, & state mapping
│   ├── correlation_engine.py        # Rule-based multi-event attack correlation engine
│   └── state_manager.py             # System telemetry state & status summary generator formatted for ESP32
├── platform/
│   ├── __init__.py                  # OS auto-detection & platform adapter factory
│   ├── base_adapter.py              # Abstract OS telemetry primitives class
│   ├── macos.py                     # macOS native adapter (scutil, socketfilterfw, log show, system_profiler)
│   ├── windows.py                   # Windows adapter (wevtutil Event 4625/1116, PowerShell NetFirewall/PnpDevice)
│   └── linux.py                     # Linux adapter (/proc/net/arp, journalctl, ufw, lsusb, ip route)
├── monitors/
│   ├── __init__.py                  # Package exports for all 14 monitor classes
│   ├── base_monitor.py              # Threaded base class for all background security monitors
│   ├── system_monitor.py            # Sustained CPU/RAM, disk capacity, & process count resource monitor
│   ├── auth_monitor.py              # Authentication failure & login threshold detector
│   ├── network_monitor.py           # Listening ports, closed ports, connection spikes, & port scan monitor
│   ├── network_device_monitor.py    # Local subnet device inventory (IP/MAC joiners & disconnects)
│   ├── gateway_monitor.py           # Default gateway IP & MAC spoofing shift monitor
│   ├── dns_monitor.py               # System DNS server change, untrusted DNS, query burst, & failure monitor
│   ├── firewall_monitor.py          # Host firewall state (enabled/disabled), config change, & block event monitor
│   ├── usb_monitor.py               # USB insertion, removal, storage flag, vendor/PID/serial, & trust monitor
│   ├── process_monitor.py           # Process spawn bursts, restart loops, memory/CPU hogs, & network activity monitor
│   ├── file_integrity_monitor.py    # SHA-256 baseline FIM, permission mode changes, & mass file modification monitor
│   ├── persistence_monitor.py       # LaunchAgents/LaunchDaemons, Registry Run keys, & systemd autostart monitor
│   ├── arp_monitor.py               # Gateway MAC spoofing & ARP collision monitor
│   └── external_security_monitor.py # Ingestion adapter for Windows Defender, XProtect, ClamAV, & 3rd-party AV alerts
├── storage/
│   ├── __init__.py
│   ├── database.py                  # SQLite database manager & analytical relational query helpers
│   ├── ersm.db                      # Persistent SQLite database file
│   └── fim_baseline.json            # SHA-256 FIM baseline hash storage
├── transport/
│   ├── __init__.py
│   ├── base_transport.py            # Abstract transport interface
│   ├── console.py                   # Terminal status dashboard & colorized event logger
│   ├── json_logger.py               # JSON Lines (events.jsonl) file appender
│   └── serial_transport.py          # PySerial hardware transport interface for ESP32 communication
├── utils/
│   ├── __init__.py
│   ├── logger.py                    # Application logging setup
│   └── simulation.py                # Safe simulation engine for generating mock security events
├── docs/
│   └── ESP32_PROGRAMMING_GUIDE.md   # Complete ESP32 hardware wiring, pinout, & C++ Arduino firmware guide
├── tests/                           # Comprehensive unit test suite
│   ├── test_event.py                # SecurityEvent schema tests
│   ├── test_risk_engine.py          # Risk scoring, rate-limiting, & decay tests
│   ├── test_correlation_engine.py   # Multi-event correlation rule tests
│   ├── test_database.py             # SQLite database storage & query tests
│   ├── test_fim.py                  # File Integrity Monitor hash & baseline tests
│   ├── test_monitors.py             # System & ARP monitor tests
│   └── test_new_monitors.py         # USB, Firewall, DNS, Gateway, Device, Process, & External security tests
├── requirements.txt                 # Dependencies (psutil, watchdog, pyserial)
└── README.md                        # Complete project documentation
```

---

## 3. Host Agent Security Monitoring Modules

The Host Agent includes 14 independent, non-blocking monitoring modules running in dedicated background threads:

### 1. USB Security Monitor (`monitors/usb_monitor.py`)
- **Monitors**: USB device insertion, removal, storage device connection flags, Vendor ID, Product ID, and Serial Numbers.
- **Trust Classification**: Compares connected USB devices against configured whitelists (`trusted_vendors`, `trusted_devices`, `trusted_serials`).
- **Events**: `USB_CONNECTED`, `USB_REMOVED`, `UNKNOWN_USB_DEVICE`, `TRUSTED_USB_DEVICE`, `USB_MALWARE_ALERT`.

### 2. Firewall Monitor (`monitors/firewall_monitor.py`)
- **Monitors**: Host firewall enabled/disabled state, firewall policy rule changes, and repeated connection block events.
- **Adapters**: Integrates with macOS `socketfilterfw`, Windows `Get-NetFirewallProfile`, and Linux `ufw`.
- **Events**: `FIREWALL_DISABLED`, `FIREWALL_CONFIGURATION_CHANGED`, `FIREWALL_BLOCK_EVENT`.

### 3. DNS Monitor (`monitors/dns_monitor.py`)
- **Monitors**: System DNS resolver IP changes, untrusted/rogue DNS servers, DNS resolution failure bursts, and query request spikes.
- **Events**: `DNS_SERVER_CHANGED`, `DNS_ANOMALY`, `DNS_FAILURE`.

### 4. Gateway Monitor (`monitors/gateway_monitor.py`)
- **Monitors**: Default gateway IP changes and unexpected gateway MAC address shifts (protecting against ARP spoofing/MITM).
- **Events**: `GATEWAY_CHANGED`, `GATEWAY_MAC_CHANGED`.

### 5. Port & Connection Monitor (`monitors/network_monitor.py`)
- **Monitors**: Active listening ports, new open ports, closed ports, inbound/outbound connection volume anomalies, connection spikes, and port scans.
- **Events**: `NEW_LISTENING_PORT`, `LISTENING_PORT_REMOVED`, `OUTBOUND_CONNECTION_ANOMALY`, `INBOUND_CONNECTION_ANOMALY`, `CONNECTION_SPIKE`, `PORT_SCAN_SUSPECTED`.

### 6. Network Device Discovery Monitor (`monitors/network_device_monitor.py`)
- **Monitors**: Maintains an inventory of active hosts on the local subnet via ARP table inspection.
- **Events**: `NEW_NETWORK_DEVICE`, `DEVICE_REMOVED`.

### 7. Process Behavior Monitor (`monitors/process_monitor.py`)
- **Monitors**: Process spawn bursts, process crash/restart loops, per-process high CPU/RAM usage, unexpected parent-child process execution, and process network sockets.
- **Events**: `PROCESS_CPU_ANOMALY`, `PROCESS_MEMORY_ANOMALY`, `PROCESS_SPAWN_BURST`, `PROCESS_RESTART_LOOP`, `PROCESS_NETWORK_ACTIVITY`.

### 8. File Activity & Integrity Monitor (`monitors/file_integrity_monitor.py`)
- **Monitors**: SHA-256 hash modifications, file permissions changes (`chmod`), rapid file creation/deletion, and mass file modification bursts (ransomware indicators).
- **Events**: `MASS_FILE_CHANGE`, `FILE_PERMISSION_CHANGED`, `FILE_CREATED`, `FILE_DELETED`, `FILE_INTEGRITY_CHANGE`.

### 9. System Resource Monitor (`monitors/system_monitor.py`)
- **Monitors**: Sustained CPU usage > threshold, sustained RAM usage > threshold, critical disk usage, and high total process counts.
- **Events**: `CPU_RESOURCE_ALERT`, `MEMORY_RESOURCE_ALERT`, `DISK_RESOURCE_ALERT`, `PROCESS_COUNT_ALERT`.

### 10. External Security Tool Integration Adapter (`monitors/external_security_monitor.py`)
- **Monitors**: Windows Defender operational logs, macOS XProtect/log show, Linux auditd/ClamAV logs, and third-party AV tools.
- **Events**: `MALWARE_ALERT`, `THREAT_DETECTED`, `SECURITY_WARNING`. Demarcates `source: REPORTED_BY_EXTERNAL_SECURITY_TOOL`.

### 11. Authentication Monitor (`monitors/auth_monitor.py`)
- **Monitors**: System authentication failures and failed login thresholds.
- **Events**: `AUTH_FAILURE_THRESHOLD`.

### 12. ARP Monitor (`monitors/arp_monitor.py`)
- **Monitors**: ARP mapping collisions and gateway spoofing.
- **Events**: `ARP_MAPPING_CONFLICT`, `GATEWAY_MAC_CHANGED`.

### 13. Persistence Monitor (`monitors/persistence_monitor.py`)
- **Monitors**: Auto-start persistence directories (LaunchAgents, LaunchDaemons, Windows Registry Run keys, systemd service units).
- **Events**: `PERSISTENCE_CHANGE`.

---

## 4. Core Engines & Data Model

### Standardized Security Event Model (`core/event.py`)
Every security event produced by ERSM adheres to a unified data schema:
```python
@dataclass
class SecurityEvent:
    category: str       # SYSTEM, NETWORK, AUTHENTICATION, PROCESS, INTEGRITY, USB, FIREWALL, DNS, GATEWAY, PORT, DEVICE, RESOURCE, FILE_ACTIVITY, MALWARE, CORRELATION
    event: str          # Standardized event identifier string
    severity: str       # INFO, LOW, MEDIUM, HIGH, CRITICAL
    message: str        # Human-readable event description
    risk: int = 0       # Assigned risk score (0-100)
    confidence: str = EventConfidence.MEDIUM.value  # LOW, MEDIUM, HIGH
    timestamp: str      # ISO-8601 UTC timestamp
    host: str           # Local hostname
    platform: str       # Windows, macOS, or Linux
    source: str         # DETECTED_BY_ERSM or REPORTED_BY_EXTERNAL_SECURITY_TOOL
    module: str         # Originating monitor module name
    metadata: Dict      # Detailed event key-value telemetry
```

### Risk Engine (`core/risk_engine.py`)
- **Scoring Range**: 0 to 100.
- **Severity Weighting**: `INFO: 0`, `LOW: 5`, `MEDIUM: 15`, `HIGH: 30`, `CRITICAL: 50`.
- **Rate-Limiting / Duplicate Suppression**: Duplicate events within 60 seconds receive reduced risk contributions (1.0x -> 0.5x -> 0.1x).
- **Dynamic Time Decay**: Risk score decays automatically over time (default: -2 points every 10 seconds).
- **Risk Level Status Mapping**:
  - `0 - 29`: `SAFE`
  - `30 - 59`: `WARNING`
  - `60 - 79`: `HIGH`
  - `80 - 100`: `CRITICAL`

### Event Correlation Engine (`core/correlation_engine.py`)
Evaluates multi-event attack sequences within sliding time windows (default: 60 seconds). Built-in rules include:
1. **Possible Intrusion**: `AUTH_FAILURE_THRESHOLD` + `NEW_LISTENING_PORT` + `PROCESS_NETWORK_ACTIVITY` -> `POSSIBLE_INTRUSION`
2. **Possible Network Attack**: `GATEWAY_MAC_CHANGED` / `ARP_ANOMALY` + `DNS_SERVER_CHANGED` + `GATEWAY_CHANGED` -> `POSSIBLE_NETWORK_ATTACK`
3. **Suspicious System Alteration**: `MASS_FILE_CHANGE` + `PERSISTENCE_CHANGE` / `PROCESS_RESTART_LOOP` -> `SUSPICIOUS_SYSTEM_ALTERATION`

### SQLite Database Engine (`storage/database.py`)
Stores every security event into `storage/ersm.db` with relational schema and indexes. Includes CLI query helpers:
- `get_recent_events(limit)`
- `get_highest_risk_events(limit)`
- `get_events_by_category(category)`
- `get_daily_counts()` / `get_events_by_day()`

---

## 5. ESP32 Hardware Console Integration Guide

The ESP32 Hardware Console is an independent physical unit running custom C++ firmware. It receives telemetry packets over USB Serial from the Host Agent and renders visual and audible alarms out-of-band.

### Hardware Pin Mapping (ESP32 DevKit V1)

| Component | ESP32 Pin | Interface / Type | Description |
| :--- | :--- | :--- | :--- |
| **OLED Display SDA** | GPIO 21 | I2C Data | SSD1306 128x64 Graphic Display (Address `0x3C`) |
| **OLED Display SCL** | GPIO 22 | I2C Clock | Pull-up resistors integrated |
| **RGB LED - Red** | GPIO 25 | PWM Output | Current limiting resistor 220Ω |
| **RGB LED - Green** | GPIO 26 | PWM Output | Current limiting resistor 220Ω |
| **RGB LED - Blue** | GPIO 27 | PWM Output | Current limiting resistor 220Ω |
| **Piezo Siren (+)** | GPIO 14 | PWM / Tone Out | Active siren buzzer output |
| **Mute/Ack Button** | GPIO 12 | Digital In (Pull-up)| Active LOW button (Connect to GND) |
| **USB Serial UART** | GPIO 3 (RX), GPIO 1 (TX) | UART0 @ 115200 | Transmits/Receives JSON packets from Host Agent |

### ESP32 FreeRTOS Dual-Core Firmware Architecture
- **Core 0 (`UART_Receive_Task`)**: Dedicated to reading line-buffered serial data, deserializing JSON using `ArduinoJson`, and pushing messages to a FreeRTOS Queue.
- **Core 1 (`UI_Alert_Task`)**: Renders SSD1306 OLED graphic dashboard, updates RGB status LEDs based on risk levels (`SAFE` = Green, `WARNING` = Orange, `HIGH` = Red, `CRITICAL` = Flashing Red), triggers piezo buzzer sirens, and handles mute button debouncing.

For full ESP32 Arduino source code, detailed circuit diagrams, and step-by-step flashing instructions, see [docs/ESP32_PROGRAMMING_GUIDE.md](docs/ESP32_PROGRAMMING_GUIDE.md).

---

## 6. Installation & Execution Guide

### Step 1: Clone Repository & Create Virtual Environment
```bash
cd ERSM
python3 -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Initialize FIM SHA-256 Baseline
```bash
python3 main.py --fim-init
```

### Step 3: Configure `config/config.json`
Set your desired monitor thresholds, whitelists, and enable serial transport if an ESP32 is attached:
```json
"transport": {
  "serial": {
    "enabled": true,
    "port": "/dev/tty.usbmodem14101",
    "baudrate": 115200
  }
}
```

### Step 4: Launch Host Agent Continuous Daemon
```bash
python3 main.py
```

---

## 7. Simulation Mode, CLI Queries & Testing

### Simulation Mode
Safely inject mock security events to test detection rules, risk engine scoring, correlation rules, and hardware alert responses without altering system configuration:

```bash
# Inject all 13 simulated security event scenarios sequentially
python3 main.py --simulate-all

# Inject specific simulated events
python3 main.py --simulate USB_MALWARE_ALERT
python3 main.py --simulate FIREWALL_DISABLED
python3 main.py --simulate DNS_ATTACK
python3 main.py --simulate PROCESS_RESTART_LOOP
```

Available simulation event keys:
`AUTH_FAILURE`, `ARP_ANOMALY`, `PORT_SCAN`, `DNS_ATTACK`, `USB_CONNECTED`, `UNKNOWN_USB_DEVICE`, `USB_MALWARE_ALERT`, `NEW_NETWORK_DEVICE`, `CPU_RESOURCE_ALERT`, `FILE_PERMISSION_CHANGED`, `MASS_FILE_CHANGE`, `PROCESS_RESTART_LOOP`, `FIREWALL_DISABLED`.

### SQLite Analytical Queries CLI
Query recorded security events directly from the command line:

```bash
# Query N recent security events
python3 main.py --query-recent 15

# Query highest risk score events
python3 main.py --query-high-risk

# Query events by category
python3 main.py --query-category USB
python3 main.py --query-category FIREWALL

# Query daily aggregated security event counts
python3 main.py --query-daily
```

### Automated Unit Test Suite
Execute unit tests covering all core engines, storage helpers, and 14 monitor modules:

```bash
python3 -m unittest discover tests
```

---

## 8. Security Philosophy & Best Practices

1. **Passive Telemetry Polling**: All monitors poll system state non-intrusively without kernel driver modifications.
2. **Honest Confidence Attribution**: Suspected anomalies express appropriate confidence levels (`LOW`, `MEDIUM`, `HIGH`) rather than declaring false certainty.
3. **Source Attribution**: ERSM explicitly distinguishes alerts detected by ERSM monitors (`source: DETECTED_BY_ERSM`) vs alerts ingested from external tools (`source: REPORTED_BY_EXTERNAL_SECURITY_TOOL`).
4. **Out-of-Band Hardware Decoupling**: Critical alerts are streamed over isolated USB Serial to the ESP32 hardware console, preventing software-based alert suppression.
