# Embedded Runtime Security Monitor (ERSM) - Host Agent

> **B.Tech CSE Capstone Project**  
> **Production-Quality Prototype: Host-Side Cybersecurity Monitoring & Hardware Transport Interface**

---

## 1. Project Overview

**Embedded Runtime Security Monitor (ERSM)** is a hardware-assisted host security monitoring system. The **ERSM Host Agent** runs continuously in the background from boot to shutdown, collecting host and network security telemetry, converting raw indicators into standardized security events, evaluating risk with dynamic time decay and rate-limiting, correlating multi-layered threats, and publishing alerts to both persistent databases (SQLite & JSONL) and an outgoing USB Serial transport interface for an external ESP32 hardware device.

```
+---------------------------------------------------------------------------------------+
|                                    ERSM HOST AGENT                                    |
|                                                                                       |
|  +--------------------+   +---------------------+   +------------------------------+  |
|  | System Monitors    |   | Auth & Process      |   | Network, ARP & FIM           |  |
|  | (CPU/RAM/Disk/USB) |   | (Log Streams/Spawns)|   | (Ports/Gateway/Hashes/DNS)   |  |
|  +---------+----------+   +----------+----------+   +--------------+---------------+  |
|            |                         |                             |                  |
|            +-------------------------+-----------------------------+                  |
|                                      v                                                |
|                        +---------------------------+                                  |
|                        |   Thread-Safe Event Bus   |                                  |
|                        +-------------+-------------+                                  |
|                                      v                                                |
|            +-------------------------+-----------------------------+                  |
|            v                         v                             v                  |
|  +-------------------+    +--------------------+        +--------------------+        |
|  | Risk Engine       |    | Correlation Engine |        | SQLite & JSONL     |        |
|  | (Decay & Limits)  |    | (Multi-Event Rules)|        | Database Storage   |        |
|  +---------+---------+    +----------+---------+        +----------+---------+        |
|            |                         |                             |                  |
|            +-------------------------+-----------------------------+                  |
|                                      v                                                |
|                        +---------------------------+                                  |
|                        | Global State Manager &    |                                  |
|                        | Transport Interface       |                                  |
|                        +-------------+-------------+                                  |
|                                      |                                                |
+--------------------------------------|------------------------------------------------+
                                       v  (USB Serial Protocol / JSON Stream)
                       +-------------------------------+
                       |  ESP32 Hardware Security Unit |
                       |  (OLED Display / LED Status)  |
                       +-------------------------------+
```

---

## 2. Architecture & Directory Structure

```
ersm-agent/
├── main.py                          # CLI entry point, daemon orchestrator, and simulation runner
├── config/
│   └── config.json                  # Thresholds, intervals, risk weights, paths, and transport config
├── core/
│   ├── __init__.py
│   ├── event.py                     # Standardized SecurityEvent data model & schema validation
│   ├── event_bus.py                 # Thread-safe pub-sub Event Bus
│   ├── risk_engine.py               # Risk scoring (0-100), decay, rate-limiting, and state mapping
│   ├── correlation_engine.py        # Multi-event correlation rules engine
│   └── state_manager.py             # Status summary generator formatted for ESP32 status packets
├── platform/
│   ├── __init__.py                  # OS auto-detection & adapter factory
│   ├── base_adapter.py              # Abstract platform adapter class
│   ├── macos.py                     # macOS native adapter (scutil, route, log stream, system_profiler)
│   ├── windows.py                   # Windows adapter (wevtutil Event 4625, Registry, ipconfig, PnpDevice)
│   └── linux.py                     # Linux adapter (/proc/net/arp, journalctl, /var/log/auth.log, ip route)
├── monitors/
│   ├── __init__.py
│   ├── base_monitor.py              # Threaded base class for all security monitors
│   ├── system_monitor.py            # Duration-based CPU/RAM/Disk anomaly detector
│   ├── auth_monitor.py              # Login failure & threshold detector
│   ├── network_monitor.py           # Port scan, connection flood, and listening port monitor
│   ├── arp_monitor.py               # Gateway MAC spoofing & ARP collision monitor
│   ├── process_monitor.py           # Process spawn bursts and memory/CPU hog monitor
│   ├── file_integrity_monitor.py    # SHA-256 baseline FIM & mass file modification detector
│   ├── persistence_monitor.py       # LaunchAgents/LaunchDaemons, Registry, & systemd monitor
│   ├── dns_monitor.py               # System DNS resolver modification monitor
│   ├── usb_monitor.py               # External USB hardware insertion monitor
│   └── external_security_monitor.py # Ingestion adapter for external AV/Firewall alerts
├── storage/
│   ├── __init__.py
│   └── database.py                  # SQLite event store and relational analytical query engine
├── transport/
│   ├── __init__.py
│   ├── base_transport.py            # Abstract transport interface
│   ├── console.py                   # Terminal status dashboard & colorized event logger
│   ├── json_logger.py               # JSON Lines (events.jsonl) file appender
│   └── serial_transport.py          # PySerial hardware transport interface for ESP32
├── utils/
│   ├── __init__.py
│   ├── logger.py                    # Application logging setup
│   └── simulation.py                # Safe simulation engine for generating fake security events
├── tests/                           # Comprehensive unit test suite
│   ├── test_event.py
│   ├── test_risk_engine.py
│   ├── test_correlation_engine.py
│   ├── test_fim.py
│   └── test_monitors.py
├── logs/
│   └── events.jsonl                 # Standardized JSONL log file output
├── storage/
│   ├── ersm.db                      # SQLite database file
│   └── fim_baseline.json            # Trusted file integrity hash baseline
├── requirements.txt                 # Python dependencies manifest
└── README.md                        # Project documentation
```

---

## 3. Installation Instructions

### Prerequisites
- Python 3.9+ installed on target operating system (macOS, Linux, or Windows).

### Step-by-Step Installation

#### 1. macOS & Linux
```bash
# Clone or navigate to the project directory
cd ersm-agent

# Create a Python virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

#### 2. Windows (PowerShell / Command Prompt)
```powershell
# Navigate to project directory
cd ersm-agent

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

---

## 4. Running the ERSM Agent

### Mode 1: Continuous Background Security Daemon
Runs all background monitors, calculates real-time risk, saves to SQLite/JSONL, and displays the live terminal dashboard:

```bash
python3 main.py
```

Example Terminal Dashboard Output:
```
==================================================
             ERSM HOST AGENT DASHBOARD            
==================================================
STATUS: SAFE
RISK SCORE: 12/100
CPU: 21% | RAM: 63% | NETWORK: ONLINE
Total Alerts Detected: 2
--------------------------------------------------
Recent Events:
  [INFO] AGENT_STARTED: ERSM Host Agent started successfully on macOS.
  [LOW] RESOURCE_ANOMALY: CPU usage sustained at 91.2% for 30s.
==================================================
```

### Mode 2: Simulation Mode (Testing Security Rules)
Safely test individual or all security event rules without modifying system state:

```bash
# Simulate specific events
python3 main.py --simulate AUTH_FAILURE
python3 main.py --simulate ARP_ANOMALY
python3 main.py --simulate PORT_SCAN
python3 main.py --simulate FILE_INTEGRITY_CHANGE
python3 main.py --simulate RESOURCE_ANOMALY
python3 main.py --simulate MALWARE_ALERT

# Simulate full event sequence
python3 main.py --simulate-all
```

### Mode 3: File Integrity Baseline Management
Initialize or inspect the trusted file hash baseline for configured sensitive directories:

```bash
# Create or update trusted baseline
python3 main.py --fim-init
```

### Mode 4: Analytical Database Queries
Query stored security records from the SQLite database (`storage/ersm.db`):

```bash
# Query recent 10 events
python3 main.py --query-recent 10

# Query highest-risk events
python3 main.py --query-high-risk
```

### Mode 5: Running Unit Tests
Execute the complete test suite to verify detection logic, risk math, and correlation rules:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

---

## 5. Core Detection Modules & Standard Event Schema

### Standardized Security Event Schema
Every monitor emits standardized JSON security events:

```json
{
    "timestamp": "2026-07-30T21:30:00Z",
    "host": "MacBook-Pro.local",
    "platform": "macOS",
    "category": "AUTHENTICATION",
    "event": "AUTH_FAILURE_THRESHOLD",
    "severity": "HIGH",
    "confidence": "HIGH",
    "risk": 30,
    "source": "DETECTED_BY_ERSM",
    "message": "Authentication Failure Threshold Exceeded: 5 failures within 60 seconds.",
    "metadata": {
        "failure_count": 5,
        "threshold": 5,
        "window_seconds": 60
    }
}
```

### Supported Categories & Severities
- **Categories**: `AUTHENTICATION`, `NETWORK`, `SYSTEM`, `PROCESS`, `INTEGRITY`, `MALWARE`, `CORRELATION`.
- **Severities**: `INFO` (+0 risk), `LOW` (+5 risk), `MEDIUM` (+15 risk), `HIGH` (+30 risk), `CRITICAL` (+50 risk).
- **Confidence**: `LOW`, `MEDIUM`, `HIGH`.

---

## 6. Risk Scoring & Correlation Engine Math

### Global Risk Score Formula
Global risk $R \in [0, 100]$ is mapped to system health statuses:
- **0 – 29**: `SAFE`
- **30 – 59**: `WARNING`
- **60 – 79**: `HIGH RISK`
- **80 – 100**: `CRITICAL`

#### Rate Limiting (Anti-Spam Multiplier)
To prevent a rapid flood of duplicate events from driving risk score immediately to 100:
$$\text{Risk}_{\text{added}} = \text{BasePoints} \times M_{\text{repeat}}$$
Where:
- First event: $M = 1.0$
- Second duplicate event in 60s: $M = 0.5$
- Subsequent duplicates: $M = 0.1$

#### Dynamic Risk Decay
When no new alerts occur, risk decays periodically over time:
$$R_{t + \Delta t} = \max(0, R_t - \text{DecayAmount})$$
Default decay: $-2$ points every 10 seconds.

### Security Correlation Engine
Combines multi-layer low/medium events into correlated security incidents:
1. `AUTH_FAILURE_THRESHOLD` + `NEW_NETWORK_DEVICE` + `NEW_LISTENING_PORT` $\rightarrow$ `CORRELATED_SECURITY_INCIDENT`
2. `ARP_MAPPING_CONFLICT` + `DNS_SERVER_CHANGED` + `GATEWAY_MAC_CHANGED` $\rightarrow$ `NETWORK_INTEGRITY_INCIDENT`
3. `PORT_SCAN_SUSPECTED` + `CONNECTION_FLOOD_ANOMALY` $\rightarrow$ `NETWORK_ATTACK_PATTERN`
4. `MASS_FILE_CHANGE` + `PERSISTENCE_CHANGE` $\rightarrow$ `SUSPICIOUS_SYSTEM_ALTERATION`

---

## 7. Cross-Platform Support (macOS, Windows, Linux)

The `platform/` package uses an auto-detecting factory pattern (`get_platform_adapter()`) that binds native OS commands cleanly:

| Feature | macOS (`macos.py`) | Windows (`windows.py`) | Linux (`linux.py`) |
| :--- | :--- | :--- | :--- |
| **Gateway & MAC** | `route -n get default` | `ipconfig` / `route print` | `ip route show default` |
| **ARP Resolution** | `arp -a` | `arp -a` | `/proc/net/arp` |
| **Auth Failures** | macOS Unified Log (`log show`) | Windows Event Log (`wevtutil 4625`) | `/var/log/auth.log` / `journalctl` |
| **Persistence** | `LaunchAgents` / `LaunchDaemons` | Startup folders & Registry Run | `systemd`, `init.d`, `autostart` |
| **USB Devices** | `system_profiler SPUSBDataType` | `PowerShell Get-PnpDevice` | `lsusb` / `/sys/bus/usb` |

---

## 8. ESP32 Hardware Integration Guide

The ERSM Host Agent communicates with an external ESP32 microcontroller over USB Serial (baud rate: 115200).

```
+------------------+                    +------------------+
|                  |     USB Serial     |                  |
| ERSM Host Agent  | -----------------> | ESP32 Hardware   |
| (Python)         |  JSON Frame (\n)   | Microcontroller  |
|                  |                    | (OLED / LEDs)    |
+------------------+                    +------------------+
```

### JSON Stream Packet Protocol

#### 1. Periodic Status Payload (`TYPE: STATUS`)
Sent every 1–2 seconds to update the ESP32 screen and LED indicators:
```json
{
  "type": "STATUS",
  "data": {
    "status": "WARNING",
    "risk": 42,
    "cpu": 34,
    "ram": 61,
    "network": "ONLINE",
    "active_alerts": 3,
    "last_event": "GATEWAY_MAC_CHANGED",
    "timestamp": "2026-07-30T21:30:00Z"
  }
}
```

#### 2. Instant Alert Event Payload (`TYPE: EVENT`)
Transmitted immediately when a security event is detected:
```json
{
  "type": "EVENT",
  "data": {
    "category": "NETWORK",
    "event": "PORT_SCAN_SUSPECTED",
    "severity": "HIGH",
    "risk": 90,
    "message": "Rapid port scan pattern detected from 192.168.1.150"
  }
}
```

### Enabling Serial Hardware in `config/config.json`
```json
"transport": {
  "serial": {
    "enabled": true,
    "port": "/dev/tty.usbmodem14101",
    "baudrate": 115200
  }
}
```
If `pyserial` is not installed or no ESP32 is plugged in, `SerialTransport` safely logs packets in dry-run mode without crashing the agent.

---

## 9. Boot-to-Shutdown Background Service Configuration

### macOS LaunchDaemon (`/Library/LaunchDaemons/com.ersm.agent.plist`)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ersm.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/youruser/ersm-agent/venv/bin/python3</string>
        <string>/Users/youruser/ersm-agent/main.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/Users/youruser/ersm-agent</string>
</dict>
</plist>
```
Activate with: `sudo launchctl load /Library/LaunchDaemons/com.ersm.agent.plist`

### Linux systemd Service (`/etc/systemd/system/ersm.service`)
```ini
[Unit]
Description=Embedded Runtime Security Monitor (ERSM) Host Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ersm-agent
ExecStart=/opt/ersm-agent/venv/bin/python3 /opt/ersm-agent/main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```
Activate with: `sudo systemctl enable --now ersm.service`

---

## 10. License & Capstone Citation

Developed for B.Tech Computer Science & Engineering (CSE) Capstone Project.  
**System**: Embedded Runtime Security Monitor (ERSM)  
**Author**: Heramb Kataru  
**Year**: 2026
