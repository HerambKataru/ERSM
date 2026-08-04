# ESP32 Hardware Console Programming Guide - ERSM Project

> **Embedded Runtime Security Monitor (ERSM)**  
> **Capstone Project Hardware Integration Guide for ESP32 Security Console**

---

## 1. Executive Summary & Hardware Architecture

The **ESP32 Hardware Console** serves as an isolated, physical security telemetry and alerting unit for the Embedded Runtime Security Monitor (ERSM). By decoupling the physical status display and alert siren from the monitored host system, ERSM ensures that security alerts (such as ransomware file modifications, firewall tampering, or unauthorized USB insertions) cannot be silently suppressed by malicious host-level processes.

### Key Hardware Responsibilities
1. **Real-time Status Display**: Visual representation of global risk score (0-100), risk status label (`SAFE`, `WARNING`, `HIGH`, `CRITICAL`), host CPU/RAM usage, and active threat counters on an I2C OLED display (SSD1306 128x64).
2. **Visual & Audible Alarm Subsystem**:
   - **RGB Status LED / Tri-Color Indicator**: Color-coded risk status (Green = SAFE, Yellow = WARNING, Orange/Red = HIGH, Flashing Red = CRITICAL).
   - **Active Piezo Buzzer**: Audible alert tones triggered on high/critical security events.
3. **Physical User Interaction**: Pushbutton for muting active audible sirens and acknowledging security alerts.
4. **Isolated Serial Receiver**: Reads non-blocking JSON packets transmitted over USB Serial (UART) by the ERSM Host Agent (`SerialTransport`).

---

## 2. Hardware Wiring & Pin Mapping

### Pinout Table (ESP32 DevKit V1)

| Component | ESP32 Pin | Interface / Type | Notes |
| :--- | :--- | :--- | :--- |
| **OLED Display SDA** | GPIO 21 | I2C Data | SSD1306 (0x3C I2C Address) |
| **OLED Display SCL** | GPIO 22 | I2C Clock | Pull-up resistors integrated |
| **RGB LED - Red** | GPIO 25 | PWM / Digital Out | Current limiting resistor 220Ω |
| **RGB LED - Green** | GPIO 26 | PWM / Digital Out | Current limiting resistor 220Ω |
| **RGB LED - Blue** | GPIO 27 | PWM / Digital Out | Current limiting resistor 220Ω |
| **Piezo Buzzer (+)** | GPIO 14 | PWM / Tone Out | Transistor driver / direct drive |
| **Mute/Ack Button** | GPIO 12 | Digital In (Pull-up)| Active LOW (Connect to GND) |
| **USB Serial Rx/Tx** | GPIO 3 (RX0), GPIO 1 (TX0) | UART0 / USB | Internal CP2102/CH340 chip |

---

## 3. Communication Protocol Specification

The ESP32 receives raw JSON frames from the ERSM Host Agent over USB Serial (`115200` baud rate, 8 data bits, no parity, 1 stop bit). Each frame is terminated by a newline character (`\n`).

### Frame Type 1: Status Telemetry Packet (`STATUS`)
Emitted by host every 2 seconds to update the live OLED telemetry screen and status LED.

```json
{
  "type": "STATUS",
  "data": {
    "risk_score": 30,
    "status_label": "WARNING",
    "total_events": 14,
    "recent_events_count": 3,
    "cpu_percent": 45.2,
    "memory_percent": 68.1,
    "active_monitors": 13,
    "timestamp": "2026-08-04T21:00:00Z"
  }
}
```

### Frame Type 2: Security Event Packet (`EVENT`)
Emitted immediately whenever a monitor or correlation rule publishes a security event.

```json
{
  "type": "EVENT",
  "data": {
    "category": "USB",
    "event": "USB_MALWARE_ALERT",
    "severity": "CRITICAL",
    "risk": 100,
    "confidence": "HIGH",
    "message": "Antivirus reported Trojan executable on USB volume",
    "module": "UsbMonitor",
    "host": "macOS-Host",
    "platform": "macOS",
    "timestamp": "2026-08-04T21:00:05Z"
  }
}
```

---

## 4. ESP32 Firmware Architecture (FreeRTOS Dual-Core)

To ensure that serial ingestion never stutters or drops packets during heavy OLED drawing operations, the ESP32 firmware utilizes **FreeRTOS Dual-Core Execution**:

- **Core 0 (`UART_Receive_Task`)**: Dedicated to reading line-buffered serial data, executing JSON deserialization via `ArduinoJson`, and pushing parsed messages into a thread-safe Queue.
- **Core 1 (`UI_Alert_Task`)**: Processes queued messages, updates the OLED graphic display, computes RGB LED colors, handles buzzer tone patterns, and checks pushbutton debouncing.

```
       +------------------------------------+
       |   USB Serial (UART0 115200 baud)   |
       +-----------------+------------------+
                         |
                         v
       +------------------------------------+
       |  Core 0: UART_Receive_Task         |
       |  - Line Buffer Assembly (\n)       |
       |  - ArduinoJson Deserialization     |
       +-----------------+------------------+
                         |
                         v (FreeRTOS Queue)
       +------------------------------------+
       |  Core 1: UI_Alert_Task             |
       |  - OLED Display Drawing (SSD1306)  |
       |  - RGB LED Color & PWM Control     |
       |  - Piezo Buzzer Siren Patterns     |
       |  - Mute Button Debounce            |
       +------------------------------------+
```

---

## 5. Complete Source Code: `ERSM_ESP32_Console.ino`

Below is the complete, ready-to-compile Arduino C++ firmware for the ESP32 hardware console.

```cpp
/*
 * Embedded Runtime Security Monitor (ERSM) - ESP32 Hardware Console
 * 
 * Hardware: ESP32 DevKit V1 + SSD1306 I2C OLED (128x64) + RGB LED + Buzzer + Mute Button
 * Libraries Required:
 *   - ArduinoJson (v6 or v7)
 *   - Adafruit SSD1306
 *   - Adafruit GFX Library
 */

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ArduinoJson.h>

// --- Hardware Pin Definitions ---
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define OLED_ADDRESS 0x3C

#define PIN_RED    25
#define PIN_GREEN  26
#define PIN_BLUE   27
#define PIN_BUZZER 14
#define PIN_BUTTON 12

// --- Instantiation ---
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// --- Data Structures ---
struct DeviceStatus {
  int riskScore = 0;
  char statusLabel[16] = "SAFE";
  int totalEvents = 0;
  float cpuPercent = 0.0;
  float ramPercent = 0.0;
  unsigned long lastUpdate = 0;
};

struct SecurityEventData {
  char category[20];
  char event[32];
  char severity[16];
  int risk;
  char message[64];
  char module[24];
};

enum PacketType { PACKET_STATUS, PACKET_EVENT, PACKET_UNKNOWN };

struct PacketMessage {
  PacketType type;
  DeviceStatus status;
  SecurityEventData event;
};

// --- Global State & FreeRTOS Handles ---
QueueHandle_t packetQueue;
DeviceStatus currentStatus;
volatile bool muted = false;
unsigned long muteStartTime = 0;

// --- Function Prototypes ---
void setRGBColor(uint8_t r, uint8_t g, uint8_t b);
void triggerBuzzer(const char* severity);
void drawDashboard(const DeviceStatus& stat, const char* lastEventStr);
void parseSerialLine(const char* jsonBuffer);

// --- Core 0: UART Ingestion Task ---
void UART_Receive_Task(void * pvParameters) {
  static char rxBuffer[512];
  static size_t rxIndex = 0;

  for (;;) {
    while (Serial.available() > 0) {
      char c = (char)Serial.read();
      if (c == '\n') {
        rxBuffer[rxIndex] = '\0';
        if (rxIndex > 0) {
          parseSerialLine(rxBuffer);
        }
        rxIndex = 0;
      } else if (c != '\r') {
        if (rxIndex < sizeof(rxBuffer) - 1) {
          rxBuffer[rxIndex++] = c;
        } else {
          rxIndex = 0; // Overflow reset
        }
      }
    }
    vTaskDelay(10 / portTICK_PERIOD_MS);
  }
}

// --- JSON Parsing Utility ---
void parseSerialLine(const char* jsonBuffer) {
  StaticJsonDocument<768> doc;
  DeserializationError err = deserializeJson(doc, jsonBuffer);
  if (err) return;

  const char* type = doc["type"] | "";
  PacketMessage msg;

  if (strcmp(type, "STATUS") == 0) {
    msg.type = PACKET_STATUS;
    JsonObject data = doc["data"];
    msg.status.riskScore = data["risk_score"] | 0;
    strncpy(msg.status.statusLabel, data["status_label"] | "SAFE", sizeof(msg.status.statusLabel));
    msg.status.totalEvents = data["total_events"] | 0;
    msg.status.cpuPercent = data["cpu_percent"] | 0.0;
    msg.status.ramPercent = data["memory_percent"] | 0.0;
    msg.status.lastUpdate = millis();
    xQueueSend(packetQueue, &msg, portMAX_DELAY);
  } 
  else if (strcmp(type, "EVENT") == 0) {
    msg.type = PACKET_EVENT;
    JsonObject data = doc["data"];
    strncpy(msg.event.category, data["category"] | "SYS", sizeof(msg.event.category));
    strncpy(msg.event.event, data["event"] | "UNKNOWN", sizeof(msg.event.event));
    strncpy(msg.event.severity, data["severity"] | "INFO", sizeof(msg.event.severity));
    msg.event.risk = data["risk"] | 0;
    strncpy(msg.event.message, data["message"] | "", sizeof(msg.event.message));
    strncpy(msg.event.module, data["module"] | "General", sizeof(msg.event.module));
    xQueueSend(packetQueue, &msg, portMAX_DELAY);
  }
}

// --- Setup ---
void setup() {
  Serial.begin(115200);

  // Pin Configurations
  pinMode(PIN_RED, OUTPUT);
  pinMode(PIN_GREEN, OUTPUT);
  pinMode(PIN_BLUE, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_BUTTON, INPUT_PULLUP);

  setRGBColor(0, 0, 255); // Booting Blue

  // Initialize OLED Display
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) {
    for (;;); // Lock if OLED fails
  }

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(15, 20);
  display.println("ERSM SECURITY CONSOLE");
  display.setCursor(25, 40);
  display.println("Connecting Host...");
  display.display();

  // Create FreeRTOS Queue (capacity 20)
  packetQueue = xQueueCreate(20, sizeof(PacketMessage));

  // Spawn Task on Core 0 for UART Ingestion
  xTaskCreatePinnedToCore(
    UART_Receive_Task,
    "UART_Task",
    4096,
    NULL,
    2,
    NULL,
    0
  );

  setRGBColor(0, 255, 0); // Ready Green
}

// --- Main Loop (Core 1): UI, LED & Alarm Management ---
void loop() {
  PacketMessage msg;
  static char lastEventBanner[64] = "Monitoring Active";

  // 1. Check Button for Mute/Acknowledge
  if (digitalRead(PIN_BUTTON) == LOW) {
    muted = true;
    muteStartTime = millis();
    noTone(PIN_BUZZER);
    delay(200); // Simple debounce
  }

  // Auto-reset mute after 15 seconds
  if (muted && (millis() - muteStartTime > 15000)) {
    muted = false;
  }

  // 2. Process Incoming Messages from Queue
  if (xQueueReceive(packetQueue, &msg, 50 / portTICK_PERIOD_MS) == pdTRUE) {
    if (msg.type == PACKET_STATUS) {
      currentStatus = msg.status;
    } 
    else if (msg.type == PACKET_EVENT) {
      snprintf(lastEventBanner, sizeof(lastEventBanner), "%s: %s", msg.event.severity, msg.event.event);
      if (!muted) {
        triggerBuzzer(msg.event.severity);
      }
    }
  }

  // 3. RGB LED State Machine based on Risk Score
  int score = currentStatus.riskScore;
  if (score >= 80) {
    // CRITICAL: Flashing Red
    if ((millis() / 250) % 2 == 0) setRGBColor(255, 0, 0);
    else setRGBColor(0, 0, 0);
  } else if (score >= 60) {
    // HIGH: Solid Red
    setRGBColor(255, 0, 0);
  } else if (score >= 30) {
    // WARNING: Orange/Yellow
    setRGBColor(255, 140, 0);
  } else {
    // SAFE: Solid Green
    setRGBColor(0, 255, 0);
  }

  // 4. Render OLED Dashboard
  drawDashboard(currentStatus, lastEventBanner);

  delay(100);
}

// --- RGB Helper ---
void setRGBColor(uint8_t r, uint8_t g, uint8_t b) {
  analogWrite(PIN_RED, r);
  analogWrite(PIN_GREEN, g);
  analogWrite(PIN_BLUE, b);
}

// --- Buzzer Siren Helper ---
void triggerBuzzer(const char* severity) {
  if (strcmp(severity, "CRITICAL") == 0) {
    tone(PIN_BUZZER, 2000, 400);
  } else if (strcmp(severity, "HIGH") == 0) {
    tone(PIN_BUZZER, 1500, 200);
  } else if (strcmp(severity, "MEDIUM") == 0) {
    tone(PIN_BUZZER, 1000, 100);
  }
}

// --- OLED Graphic Renderer ---
void drawDashboard(const DeviceStatus& stat, const char* lastEventStr) {
  display.clearDisplay();
  
  // Header: Status Bar
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.print("ERSM STATUS: ");
  display.println(stat.statusLabel);
  display.drawLine(0, 9, 128, 9, SSD1306_WHITE);

  // Risk Score Big Box
  display.drawRect(0, 14, 48, 32, SSD1306_WHITE);
  display.setCursor(4, 18);
  display.setTextSize(1);
  display.print("RISK");
  display.setCursor(8, 30);
  display.setTextSize(2);
  display.print(stat.riskScore);

  // Telemetry Metrics Side Panel
  display.setTextSize(1);
  display.setCursor(54, 15);
  display.printf("CPU: %.1f%%", stat.cpuPercent);
  display.setCursor(54, 26);
  display.printf("RAM: %.1f%%", stat.ramPercent);
  display.setCursor(54, 37);
  display.printf("EVT: %d", stat.totalEvents);

  // Footer: Last Event Banner
  display.drawLine(0, 48, 128, 48, SSD1306_WHITE);
  display.setCursor(0, 52);
  display.print(lastEventStr);

  display.display();
}
```

---

## 6. Installation & Deployment Guide

### Step 1: Install Required Libraries in Arduino IDE
1. Open **Arduino IDE** (v2.0 or higher).
2. Go to **Tools > Manage Libraries...** (Ctrl+Shift+I).
3. Search and install:
   - `ArduinoJson` (by Benoit Blanchon) - Version `6.21.x` or `7.x`.
   - `Adafruit SSD1306` (by Adafruit).
   - `Adafruit GFX Library` (by Adafruit).

### Step 2: Board Manager Setup
1. In Arduino IDE, go to **Settings / Preferences**.
2. Add the ESP32 Board Manager URL:
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
3. Go to **Tools > Board > Boards Manager...**, search for `esp32` by Espressif Systems and click **Install**.

### Step 3: Hardware Assembly
Connect the components according to the pinout in **Section 2**:
- Connect SSD1306 OLED SDA to `GPIO 21` and SCL to `GPIO 22`.
- Connect RGB LED pins (R, G, B) to `GPIO 25, 26, 27` with 220Ω resistors.
- Connect Piezo Buzzer (+) to `GPIO 14`.
- Connect Pushbutton to `GPIO 12` and `GND`.

### Step 4: Flash ESP32 Firmware
1. Connect ESP32 DevKit to host computer via USB cable.
2. Select Board: **Tools > Board > ESP32 Arduino > ESP32 Dev Module**.
3. Select Port: **Tools > Port > `/dev/tty.usbmodem...`** (macOS/Linux) or `COM3/COM4` (Windows).
4. Click **Upload** (Ctrl+U).

### Step 5: Configure ERSM Host Agent Serial Transport
In `config/config.json` on the Host Agent, enable the serial transport and specify the USB serial port:

```json
"transport": {
  "serial": {
    "enabled": true,
    "port": "/dev/tty.usbmodem14101",
    "baudrate": 115200
  }
}
```

Start the Host Agent:
```bash
python3 main.py
```

The ESP32 console will automatically switch from `Connecting Host...` to live telemetry displaying risk scores, system metrics, and alert triggers!

---

## 7. Troubleshooting & Common Pitfalls

| Issue | Root Cause | Resolution |
| :--- | :--- | :--- |
| **OLED display is blank / garbled** | Incorrect I2C address or reversed SDA/SCL. | Verify SSD1306 I2C address (usually `0x3C` or `0x3D`). Check SDA (GPIO21) & SCL (GPIO22). |
| **Serial packets dropped / corrupted** | Baud rate mismatch or non-blocking buffer overflow. | Ensure both Host Agent (`config.json`) and ESP32 (`Serial.begin(115200)`) use `115200` baud. |
| **ESP32 continuously reboots (Brownout Reset)** | Insufficient current supply over USB port. | Power ESP32 via a powered USB hub or add a 10µF capacitor across `5V` and `GND`. |
| **Buzzer stays on continuously** | Missing `noTone()` call or unhandled high severity state. | Press the physical ACK button (GPIO12) to mute for 15 seconds. |
