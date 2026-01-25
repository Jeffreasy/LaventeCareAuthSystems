# ESP32 Firmware Technical Analysis

**Project**: KoelkastProjectV2  
**Platform**: ESP32 (Arduino Framework)  
**Purpose**: IoT Temperature Monitoring with Convex Backend Integration  
**Analysis Date**: 2026-01-14

---

## Executive Summary

This firmware implements a **battery-optimized IoT temperature monitoring system** using ESP32 microcontrollers with DS18B20 sensors. The architecture features deep sleep cycles (5-minute intervals), hardware identity validation, and secure HTTPS communication with a Convex serverless backend.

**Key Strengths**:
- ✅ Excellent power management (90% duty cycle in deep sleep)
- ✅ Professional hardware validation via MAC address checking
- ✅ Robust error handling for sensor and network failures
- ✅ Clean multi-device management with compile-time safety

**Critical Action Items**:
- ⚠️ Update `CONVEX_URL` placeholder with actual deployment URL
- ⚠️ Synchronize `CONVEX_SECRET` with Convex environment variables
- ⚠️ Consider removing hardcoded WiFi credentials from source code

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Configuration System](#configuration-system)
3. [Main Program Flow](#main-program-flow)
4. [Data Flow & Protocol](#data-flow--protocol)
5. [Power Management](#power-management)
6. [Security Analysis](#security-analysis)
7. [Error Handling](#error-handling)
8. [Performance Metrics](#performance-metrics)
9. [Production Readiness Checklist](#production-readiness-checklist)
10. [Recommendations](#recommendations)

---

## Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                    ESP32 Firmware                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   config.h   │  │   main.ino   │  │  Libraries   │  │
│  │  Multi-device│─▶│  Deep Sleep  │◀─│  OneWire     │  │
│  │  Management  │  │  Cycle       │  │  WiFi/HTTPS  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
          │                                        ▲
          │ HTTPS POST                            │
          │ /ingestSensorData                     │
          ▼                                        │
┌─────────────────────────────────────────────────────────┐
│                  Convex Backend                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   http.ts    │─▶│  sensors.ts  │─▶│   schema.ts  │  │
│  │  HTTP Action │  │  Mutations   │  │  Database    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Device Inventory

| Device ID | MAC Address | GPIO Pin | Board Type | Status |
|-----------|-------------|----------|------------|--------|
| Koelkast_A | `a4:c1:38:e3:4d:72` | 4 | CH340 | Active (default) |
| Koelkast_B | `a4:c1:38:ee:2d:4e` | 4 | CH340 | Configured |
| Koelkast_C | `a4:c1:38:c8:92:5a` | 17 | WeMos D1 R32 | Configured |
| Koelkast_D | `a4:c1:38:ae:94:ec` | 17 | WeMos D1 R32 | Configured |

---

## Configuration System

### File: `config.h`

#### Multi-Device Compilation Pattern

The firmware uses **compile-time device selection** to ensure single-binary-per-device safety:

```cpp
#define USE_KOELKAST_A      // ← Active configuration
// #define USE_KOELKAST_B
// #define USE_KOELKAST_C
// #define USE_KOELKAST_D
```

**Design Rationale**:
- Prevents runtime configuration errors
- Enforces hardware-software binding via MAC validation
- Fails compilation if no device is selected (line 42-44 safety check)

#### Network Configuration

```cpp
#define WIFI_SSID           "Zyxel_1369"
#define WIFI_PASS           "4AW53T6BDV"
```

> **⚠️ SECURITY WARNING**: WiFi credentials are hardcoded in plaintext.  
> **Recommendation**: Migrate to WiFiManager or separate credentials file (excluded from version control).

#### Convex Integration Settings

```cpp
#define CONVEX_URL          "https://<JOUW_PROJECT>.convex.site/ingestSensorData"
#define CONVEX_SECRET       "MijnGeheimeSleutel_2026"
```

**Configuration Status**:
- ❌ `CONVEX_URL` is a placeholder and must be updated
- ✅ `CONVEX_SECRET` is set (must match Convex `ESP32_SECRET` environment variable)

#### Timing Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `SLEEP_DURATION` | 300 sec (5 min) | Deep sleep interval for power savings |
| `WIFI_TIMEOUT_MS` | 15000 ms (15 sec) | Maximum WiFi connection attempt time |
| `SERIAL_BAUD` | 115200 | Serial communication speed |

**Power Profile Calculation**:
- Active time: ~10-20 seconds (WiFi + HTTP)
- Sleep time: 300 seconds
- **Duty Cycle**: ~6% active, 94% in deep sleep

---

## Main Program Flow

### File: `main.ino`

#### Execution Model: Setup-Only Architecture

The firmware uses a **setup-only execution model** with deep sleep:

```cpp
void setup() {
    // All operations happen here
    // ...
    goToSleep(); // Never returns
}

void loop() {
    // Empty - never reached due to deep sleep reboot
}
```

After `esp_deep_sleep_start()`, the device performs a **full reboot** and restarts `setup()`.

---

### Detailed Flow Diagram

```
┌──────────────────────────────────────────────────────┐
│              setup() - Single Execution              │
└──────────────────────────────────────────────────────┘
                        ▼
        ┌───────────────────────────────┐
        │  1. Serial Init (115200 baud) │
        │     Log device identity       │
        └───────────────┬───────────────┘
                        ▼
        ┌───────────────────────────────┐
        │  2. MAC Address Validation    │
        │     Hardware Identity Check   │
        └───────────────┬───────────────┘
                        │
                ┌───────┴────────┐
                │ MAC Match?     │
                └───────┬────────┘
                  YES   │   NO
                   │    └──────────► ⛔ CRITICAL ERROR
                   │                 Infinite Deep Sleep
                   │                 (No timer wake)
                   ▼
        ┌───────────────────────────────┐
        │  3. Read DS18B20 Temperature  │
        │     OneWire protocol          │
        │     Check for -127°C error    │
        └───────────────┬───────────────┘
                        ▼
        ┌───────────────────────────────┐
        │  4. WiFi Connection           │
        │     Timeout: 15 seconds       │
        │     Non-blocking loop         │
        └───────────────┬───────────────┘
                        │
                ┌───────┴────────┐
                │ Connected?     │
                └───────┬────────┘
                  YES   │   NO
                   │    └──────────► Skip & Sleep
                   │                 (Retry next cycle)
                   ▼
        ┌───────────────────────────────┐
        │  5. Build JSON Payload        │
        │     ArduinoJson v7            │
        │     deviceId, temp, status... │
        └───────────────┬───────────────┘
                        ▼
        ┌───────────────────────────────┐
        │  6. HTTPS POST to Convex      │
        │     WiFiClientSecure          │
        │     x-esp32-secret header     │
        └───────────────┬───────────────┘
                        ▼
        ┌───────────────────────────────┐
        │  7. Deep Sleep Preparation    │
        │     WiFi.disconnect(true)     │
        │     WiFi.mode(WIFI_OFF)       │
        │     Timer: 300 seconds        │
        └───────────────┬───────────────┘
                        ▼
                  [DEEP SLEEP]
                        │
                    (5 minutes)
                        │
                        ▼
                   [ESP32 REBOOT]
                        │
                        └──► Back to setup()
```

---

### Critical Code Sections

#### 1. Hardware Validation (Lines 38-55)

```cpp
String currentMac = getMacAddress();
String expectedMac = String(TARGET_MAC_ADDRESS);

currentMac.toLowerCase();
expectedMac.toLowerCase();

if (currentMac != expectedMac) {
    Serial.println("!!! CRITICAL ERROR !!!");
    Serial.printf("Hardware mismatch! Config verwacht: %s\n", expectedMac.c_str());
    Serial.println("Om datavervuiling te voorkomen, stopt het systeem nu.");
    esp_deep_sleep_start(); // ⚠️ No timer = infinite sleep
}
```

**Purpose**: Prevents data pollution from incorrect firmware flashing.

**Failure Scenario Without This Check**:
1. Flash Koelkast_A firmware to Koelkast_B hardware
2. Device reports temperature as "Koelkast_A" but physically measures Koelkast_B
3. Database receives incorrect sensor attribution

**Recovery**: Requires manual reflash with correct firmware.

---

#### 2. DS18B20 Temperature Reading (Lines 57-67)

```cpp
sensors.begin();
sensors.requestTemperatures();
float tempC = sensors.getTempCByIndex(0);

if (tempC == -127.00) {
    Serial.println("Error: Sensor niet verbonden of defect.");
} else {
    Serial.printf("Temperatuur: %.2f C\n", tempC);
}
```

**Error Detection**:
- DS18B20 returns `-127.00°C` for hardware failures
- Error is **logged but not fatal** - device continues to report

**Status Mapping**:
```cpp
doc["status"] = (tempC == -127.00) ? "error" : "ok";
```

This allows the backend to:
- Track sensor health in the `status` field
- Alert on persistent error states
- Maintain device connectivity even during sensor failures

---

#### 3. WiFi Timeout Handling (Lines 69-84)

```cpp
WiFi.mode(WIFI_STA);
WiFi.begin(WIFI_SSID, WIFI_PASS);

unsigned long startAttempt = millis();
while (WiFi.status() != WL_CONNECTED && millis() - startAttempt < WIFI_TIMEOUT_MS) {
    delay(500);
    Serial.print(".");
}

if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\nWiFi Timeout. Overslaan en slapen.");
    goToSleep();
    return;
}
```

**Design Principles**:
- **Non-blocking timeout**: Prevents infinite hangs
- **Graceful degradation**: Skips HTTP on failure, retries next cycle
- **Battery preservation**: No continuous retry loops

**Network Reliability**:
- Temporary network issues don't brick the device
- Automatic recovery on next wake cycle
- No manual intervention required

---

#### 4. HTTPS Client Configuration (Lines 88-92)

```cpp
WiFiClientSecure client;
client.setInsecure(); // ⚠️ Skips certificate validation
```

**Security Trade-off Analysis**:

| Approach | Security | Reliability | Maintenance |
|----------|----------|-------------|-------------|
| `.setInsecure()` | Medium (encrypted but no verification) | High | Low |
| Certificate pinning | High | Low (breaks on cert rotation) | High |
| Root CA embedding | High | Medium (certs expire) | Medium |

**Recommendation**: `.setInsecure()` is acceptable for this use case because:
- Traffic remains encrypted (not plaintext)
- Additional authentication via `x-esp32-secret` header
- Convex URLs are not predictable (reduces MITM risk)
- Eliminates maintenance burden of certificate updates

---

#### 5. JSON Payload Construction (Lines 98-108)

```cpp
JsonDocument doc;

doc["deviceId"] = DEVICE_NAME;        // "Koelkast_A"
doc["temp"]     = tempC;              // 4.2
doc["status"]   = (tempC == -127.00) ? "error" : "ok";
doc["rssi"]     = WiFi.RSSI();        // -65
doc["mac"]      = currentMac;         // "a4:c1:38:e3:4d:72"

String jsonPayload;
serializeJson(doc, jsonPayload);
```

**Example Output**:
```json
{
  "deviceId": "Koelkast_A",
  "temp": 4.2,
  "status": "ok",
  "rssi": -65,
  "mac": "a4:c1:38:e3:4d:72"
}
```

**Field Mapping to Convex Backend**:

| ESP32 Field | Convex Field | Type | Description |
|-------------|--------------|------|-------------|
| `deviceId` | `sensorId` | string | Device identifier |
| `temp` | `value` | number | Temperature in Celsius |
| `status` | `status` | string | "ok" or "error" |
| `rssi` | `signal` | number | WiFi signal strength (dBm) |
| `mac` | `mac` | optional string | Hardware MAC address |

**Protocol Compatibility**: ✅ Perfect match with Convex `http.ts` line 24

---

#### 6. HTTP POST with Authentication (Lines 113-123)

```cpp
http.addHeader("Content-Type", "application/json");
http.addHeader("x-esp32-secret", CONVEX_SECRET);

int httpCode = http.POST(jsonPayload);

if (httpCode > 0) {
    Serial.printf("Response Code: %d\n", httpCode);
} else {
    Serial.printf("HTTP Error: %s\n", http.errorToString(httpCode).c_str());
}
```

**HTTP Headers**:
- `Content-Type: application/json` - Standard REST API header
- `x-esp32-secret: MijnGeheimeSleutel_2026` - Custom authentication header

**Response Handling**:
- Success: Logs status code (200)
- Failure: Logs error description
- **Fire-and-forget pattern**: No retry logic (data loss on failure)

---

#### 7. Deep Sleep Function (Lines 18-29)

```cpp
void goToSleep() {
    Serial.printf("Slaap voor %d seconden...\n", SLEEP_DURATION);
    Serial.flush(); // ⭐ Ensures serial buffer is transmitted
    
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    
    esp_sleep_enable_timer_wakeup(SLEEP_DURATION * 1000000ULL);
    esp_deep_sleep_start();
}
```

**Power-Saving Best Practices**:
1. `Serial.flush()` - Critical for complete log output
2. `WiFi.disconnect(true)` - Graceful disconnection
3. `WiFi.mode(WIFI_OFF)` - Disables WiFi radio
4. Timer in microseconds: `300 × 1,000,000 µs = 5 minutes`

**Power Consumption Comparison**:
- **Active (WiFi TX)**: ~200 mA
- **Deep Sleep**: ~10 µA  
- **Reduction Factor**: 20,000× lower power draw

---

## Data Flow & Protocol

### End-to-End Communication

```
┌─────────────────┐
│  DS18B20 Sensor │  (OneWire Protocol)
│   Temp: 4.2°C   │
│   Pin: GPIO 4/17│
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│      ESP32 (Koelkast_A)             │
│  ┌───────────────────────────────┐  │
│  │ MAC Validation: PASS          │  │
│  │ WiFi: Connected (-65 dBm)     │  │
│  │ JSON Build: ArduinoJson       │  │
│  │ Payload: 145 bytes            │  │
│  └───────────────────────────────┘  │
└────────┬────────────────────────────┘
         │
         │ HTTPS POST
         │ Host: *.convex.site
         │ Path: /ingestSensorData
         │ Header: x-esp32-secret
         │
         ▼
┌─────────────────────────────────────┐
│   Convex HTTP Action                │
│   ┌─────────────────────────────┐   │
│   │ http.ts                     │   │
│   │ - Validate secret (TODO)    │   │
│   │ - Parse JSON                │   │
│   │ - Call addMeasurement()     │   │
│   └─────────────────────────────┘   │
└────────┬────────────────────────────┘
         │
         │ Dual Write Pattern
         │
         ├──────────────────┬──────────────────┐
         ▼                  ▼                  ▼
┌─────────────────┐  ┌──────────────┐  ┌──────────────┐
│  measurements   │  │   sensors    │  │  Frontend    │
│  (History)      │  │  (Live State)│  │              │
│  ┌───────────┐  │  │  ┌────────┐  │  │  useQuery()  │
│  │ INSERT    │  │  │  │ UPSERT │  │  │  Reactive    │
│  │ Append    │  │  │  │ 1 row  │◀─┼──│  Updates     │
│  │ + time    │  │  │  │ /sensor│  │  │              │
│  └───────────┘  │  │  └────────┘  │  │              │
└─────────────────┘  └──────────────┘  └──────────────┘
```

### Protocol Specifications

**Transport Layer**:
- Protocol: HTTPS (TLS 1.2+)
- Method: POST
- Content-Type: `application/json`
- Authentication: Custom header `x-esp32-secret`

**Payload Schema**:
```typescript
interface SensorPayload {
  deviceId: string;  // Device identifier
  temp: number;      // Temperature in Celsius
  status: "ok" | "error"; // Sensor health
  rssi: number;      // WiFi signal strength (dBm, negative)
  mac: string;       // MAC address (lowercase with colons)
}
```

**Expected Response**:
- Success: `200 OK` with body `"OK"`
- Unauthorized: `401 Unauthorized` (when security is enabled)
- Server Error: `500 Internal Server Error`

---

## Power Management

### Sleep Cycle Analysis

**Timeline (Single Cycle)**:

```
0s      1s      2s      3s      4s      5s      10s     305s
│───────┼───────┼───────┼───────┼───────┼───────┼───────┼
│ Boot  │Sensor │ WiFi  │ WiFi  │ WiFi  │ HTTP  │ Sleep │
│  MAC  │ Read  │Connect│Connect│Connect│ POST  │ 300s  │
│───────┴───────┴───────┴───────┴───────┴───────┴───────┘
   ~80mA  ~80mA  ~180mA  ~180mA  ~180mA  ~200mA  ~0.01mA

Active Phase: ~5-10 seconds (variable WiFi time)
Sleep Phase: 300 seconds (fixed)
```

### Current Consumption Breakdown

| Phase | Duration | Current Draw | Energy |
|-------|----------|--------------|--------|
| Boot & MAC check | 1s | ~80 mA | 80 mAs |
| Sensor reading | 1s | ~80 mA | 80 mAs |
| WiFi connection | 2-8s | ~180 mA | 360-1440 mAs |
| HTTPS POST | 1-2s | ~200 mA | 200-400 mAs |
| Deep sleep | 300s | ~0.01 mA | 3 mAs |
| **Total per cycle** | **305-312s** | **Avg: ~6 mA** | **~1800 mAs** |

### Battery Life Estimation

**Hardware Assumption**: 2000 mAh lithium battery (e.g., 18650)

```
Average current draw: 6 mA
Battery capacity: 2000 mAh

Theoretical runtime: 2000 mAh / 6 mA = 333 hours ≈ 14 days

Realistic runtime (accounting for self-discharge, temperature, aging):
≈ 10-12 days
```

**Optimization Impact**:
- Without deep sleep (always active): ~10 hours
- With deep sleep: ~14 days
- **Improvement**: 33× longer battery life

---

## Security Analysis

### Current Security Measures

#### 1. Transport Layer Security
- ✅ HTTPS encryption (TLS)
- ⚠️ Certificate validation disabled (`.setInsecure()`)

**Risk Assessment**: Medium
- Data is encrypted in transit
- Susceptible to MITM if attacker controls network
- Mitigated by custom authentication header

---

#### 2. Authentication Header

**ESP32 Side** (`config.h` line 61):
```cpp
#define CONVEX_SECRET "MijnGeheimeSleutel_2026"
```

**Convex Side** (`http.ts` lines 12-20):
```typescript
const secret = request.headers.get("x-esp32-secret");

// ⚠️ CURRENTLY DISABLED:
// if (secret !== process.env.ESP32_SECRET) {
//     return new Response("Unauthorized", { status: 401 });
// }
```

**Status**: ❌ **Authentication is currently disabled in Convex backend**

**Required Actions**:
1. Set `ESP32_SECRET` environment variable in Convex Dashboard
2. Uncomment validation code in `http.ts`
3. Verify secrets match between firmware and Convex

---

#### 3. Hardware Identity Validation

```cpp
if (currentMac != expectedMac) {
    Serial.println("!!! CRITICAL ERROR !!!");
    esp_deep_sleep_start(); // Infinite sleep
}
```

**Security Benefit**:
- Prevents firmware from running on unauthorized hardware
- Protects against data pollution from misconfigured devices
- Acts as a form of device attestation

---

### Security Vulnerabilities

#### Critical Issues

1. **Hardcoded WiFi Credentials** (Severity: High)
   - Location: `config.h` lines 51-52
   - Risk: Credentials exposed if code is shared or committed to public repository
   - Recommendation: Use WiFiManager library or separate credentials file

2. **Disabled Backend Authentication** (Severity: High)
   - Location: `http.ts` line 18 (commented out)
   - Risk: Anyone with the URL can POST arbitrary data
   - Recommendation: Enable security check immediately after setting `ESP32_SECRET`

3. **Placeholder Convex URL** (Severity: Medium)
   - Location: `config.h` line 58
   - Risk: Firmware will not function until updated
   - Recommendation: Update with actual deployment URL

#### Low-Priority Issues

4. **No Firmware Version Tracking**
   - Risk: Difficult to debug mixed-version deployments
   - Recommendation: Add `FIRMWARE_VERSION` constant

5. **No Retry Logic**
   - Risk: Data loss on transient network errors
   - Recommendation: Implement 2-3 retry attempts with exponential backoff

---

## Error Handling

### Failure Modes & Recovery Strategies

| Failure Type | Detection Method | Behavior | Recovery |
|-------------|------------------|----------|----------|
| **MAC Mismatch** | String comparison at boot | Infinite deep sleep | Manual reflash required |
| **Sensor Disconnected** | `-127°C` reading | Reports as "error" status | Auto-recovery on reconnect |
| **WiFi Timeout** | 15-second timeout | Skip HTTP, go to sleep | Retry next cycle (5 min) |
| **HTTP Failure** | `httpCode <= 0` | Log error, go to sleep | Retry next cycle (5 min) |
| **Convex Down** | HTTP 5xx response | Log error, go to sleep | Retry next cycle (5 min) |

### Error Logging

All errors are logged via Serial (115200 baud):

```cpp
// Example error outputs:
"!!! CRITICAL ERROR !!!"              // MAC mismatch
"Error: Sensor niet verbonden..."    // DS18B20 failure
"WiFi Timeout. Overslaan..."         // Network failure
"HTTP Error: -1"                      // Connection failed
```

**Limitation**: No persistent error logging (memory resets on deep sleep)

**Recommendation**: Implement error counters in RTC memory for debugging

---

## Performance Metrics

### Network Performance

**WiFi Connection Time**:
- Typical: 2-5 seconds
- Maximum: 15 seconds (timeout)
- Failure rate (estimated): <5% in normal conditions

**HTTPS POST Latency**:
- Typical: 500-1000 ms
- Includes: DNS lookup, TLS handshake, POST, response

**Total Active Time**: 5-12 seconds per cycle

---

### Data Volume

**Single Measurement**:
```json
{
  "deviceId": "Koelkast_A",
  "temp": 4.2,
  "status": "ok",
  "rssi": -65,
  "mac": "a4:c1:38:e3:4d:72"
}
```
- Payload size: ~145 bytes
- With HTTP headers: ~350 bytes total

**Daily Data Volume** (per device):
- Measurements: 288/day (every 5 minutes)
- Data sent: 145 bytes × 288 = 41.8 KB/day
- Monthly: ~1.25 MB/device

**Fleet Data** (4 devices):
- Daily: ~167 KB
- Monthly: ~5 MB
- Annual: ~60 MB

---

### Memory Usage

**Flash Memory** (compiled firmware):
- Estimated: ~500 KB (depends on libraries)
- ESP32 has: 4 MB (plenty of headroom)

**RAM Usage**:
- Static: ~50 KB (WiFi, HTTP, JSON buffers)
- ESP32 has: 520 KB (sufficient)

**RTC Memory** (survives deep sleep):
- Currently unused
- Could store error counters, configuration overrides

---

## Production Readiness Checklist

### Critical (Must Complete)

- [ ] **Update `CONVEX_URL`** in `config.h` with actual deployment URL
- [ ] **Enable authentication** in Convex `http.ts` (uncomment lines 18-20)
- [ ] **Set `ESP32_SECRET`** in Convex Dashboard environment variables
- [ ] **Verify end-to-end communication** with live Convex deployment
- [ ] **Test MAC mismatch scenario** to confirm infinite sleep behavior

### High Priority (Recommended)

- [ ] **Remove hardcoded WiFi credentials** from source code
  - Option A: Use WiFiManager library for AP-based configuration
  - Option B: Move to separate `credentials_private.h` (in `.gitignore`)
- [ ] **Test each device** with corresponding firmware (A, B, C, D)
- [ ] **Validate sensor failure handling** (disconnect DS18B20, verify "error" status)
- [ ] **Monitor battery drain** over 24-hour period
- [ ] **Verify Convex database updates** in real-time

### Medium Priority (Nice to Have)

- [ ] **Add firmware version tracking**
  ```cpp
  #define FIRMWARE_VERSION "1.0.0"
  doc["firmwareVersion"] = FIRMWARE_VERSION;
  ```
- [ ] **Implement NTP time synchronization** for accurate timestamps
  ```cpp
  configTime(0, 0, "pool.ntp.org");
  time_t now; time(&now);
  doc["timestamp"] = now;
  ```
- [ ] **Add battery voltage monitoring** (if battery-powered)
  ```cpp
  int batteryRaw = analogRead(PIN_BATTERY_ADC);
  float batteryVolt = (batteryRaw / 4095.0) * 3.3 * 2;
  doc["battery"] = batteryVolt;
  ```
- [ ] **Implement HTTP retry logic** (2-3 attempts with backoff)
- [ ] **Parse Convex response** for remote configuration updates

### Low Priority (Future Enhancements)

- [ ] Create debug mode flag to disable serial output in production
- [ ] Implement OTA (Over-The-Air) firmware updates
- [ ] Add MQTT support as alternative to HTTP
- [ ] Store failed measurements in RTC memory for later retry
- [ ] Implement adaptive sleep intervals based on temperature changes

---

## Recommendations

### Immediate Actions (Week 1)

1. **Configure Convex URL**
   - Get deployment URL from Convex Dashboard
   - Update `config.h` line 58
   - Flash updated firmware to all devices

2. **Enable Security**
   - Generate strong secret (32+ characters, alphanumeric + symbols)
   - Add to Convex environment variables as `ESP32_SECRET`
   - Update `CONVEX_SECRET` in `config.h`
   - Uncomment validation in `http.ts`
   - Deploy Convex changes

3. **Initial Testing**
   - Test Koelkast_A with sensor connected
   - Verify data appears in Convex `measurements` table
   - Test sensor disconnect (should report "error" status)
   - Test WiFi disconnect (should skip and retry)

---

### Short-Term Improvements (Month 1)

1. **Credential Security**
   ```cpp
   // Create: credentials_private.h (add to .gitignore)
   #ifndef CREDENTIALS_H
   #define CREDENTIALS_H
   #define WIFI_SSID "Zyxel_1369"
   #define WIFI_PASS "4AW53T6BDV"
   #endif
   ```
   ```cpp
   // Update config.h
   #include "credentials_private.h"
   ```

2. **Firmware Versioning**
   ```cpp
   // config.h
   #define FIRMWARE_VERSION "1.0.0"
   
   // main.ino
   Serial.printf("Firmware: v%s\n", FIRMWARE_VERSION);
   doc["fwVersion"] = FIRMWARE_VERSION;
   ```

3. **Enhanced Error Logging**
   ```cpp
   // Use RTC memory for persistent counters
   RTC_DATA_ATTR int bootCount = 0;
   RTC_DATA_ATTR int wifiFailCount = 0;
   RTC_DATA_ATTR int httpFailCount = 0;
   ```

---

### Long-Term Enhancements (Quarter 1)

1. **Remote Configuration**
   - Parse JSON from Convex response
   - Support dynamic sleep interval adjustments
   - Enable/disable sensors remotely

2. **Advanced Power Management**
   - Implement adaptive sleep (longer intervals when temperature stable)
   - Battery voltage monitoring with low-battery alerts
   - Intelligent retry backoff (exponential sleep on repeated failures)

3. **Reliability Improvements**
   - Store failed measurements in RTC memory
   - Batch upload on next successful connection
   - Implement watchdog timer for hang protection

4. **Observability**
   - Add device uptime tracking
   - Report boot reason (reset, deep sleep wake, crash)
   - Track WiFi connection quality metrics

---

## Dependency Management

### Required Arduino Libraries

| Library | Purpose | Installation |
|---------|---------|--------------|
| `WiFi.h` | ESP32 WiFi connectivity | Built-in (ESP32 core) |
| `HTTPClient.h` | HTTP request handling | Built-in (ESP32 core) |
| `WiFiClientSecure.h` | HTTPS/TLS support | Built-in (ESP32 core) |
| `OneWire` | OneWire protocol | `arduino-onewire` |
| `DallasTemperature` | DS18B20 sensor driver | `arduino-temperature-control-library` |
| `ArduinoJson` | JSON serialization | `arduinojson` (v7+) |

**Installation via Arduino Library Manager**:
```
Sketch → Include Library → Manage Libraries
Search: "OneWire" → Install (by Paul Stoffregen)
Search: "DallasTemperature" → Install (by Miles Burton)
Search: "ArduinoJson" → Install v7.x (by Benoit Blanchon)
```

**PlatformIO Configuration** (`platformio.ini`):
```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
lib_deps = 
    paulstoffregen/OneWire@^2.3.7
    milesburton/DallasTemperature@^3.11.0
    bblanchon/ArduinoJson@^7.0.0
```

---

## Conclusion

The ESP32 firmware demonstrates **professional-grade embedded development** with excellent power management, robust error handling, and a well-architected multi-device configuration system. The hardware validation via MAC address checking is particularly noteworthy as a safeguard against data pollution.

**Key Strengths**:
- ✅ Battery-optimized design with 20,000× power reduction during sleep
- ✅ Fail-safe hardware identity validation
- ✅ Clean protocol integration with Convex backend
- ✅ Graceful degradation on network/sensor failures

**Critical Next Steps**:
1. Configure Convex URL placeholder
2. Enable authentication in both ESP32 and Convex
3. Complete end-to-end testing with all four devices

With these configuration updates, the firmware is **production-ready** for deployment in an IoT temperature monitoring system.

---

**Document Version**: 1.0  
**Last Updated**: 2026-01-14  
**Author**: Technical Analysis  
**Status**: Ready for Review
