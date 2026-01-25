/**
 * @project SmartCool IoT - Convex Edition
 * @version 6.0 (Robust BLE + Logging + Calibration)
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include <BLEDevice.h>
#include <esp_task_wdt.h>
#include <esp_sleep.h>
#include <ArduinoJson.h> // Zorg voor versie 7.x!
#include "esp32-hal-cpu.h"
#include "config.h"

// === REMOTE CONFIGURATION STRUCT ===
// Deze data overleeft de diepe slaap
struct DeviceConfig {
    // Timing
    int sleepDuration = SLEEP_DURATION;
    int wifiTimeout = WIFI_TIMEOUT_MS;
    int watchdogTimeout = WATCHDOG_TIMEOUT;
    int scanDuration = SCAN_DURATION; // Default 10s (total retry time)
    
    // Hardware
    int pinDS18B20 = PIN_DS18B20;
    
    // BLE Instellingen (100% Duty Cycle for Robustness)
    int bleScanInterval = 100; // ms
    int bleScanWindow = 100;   // ms (Continuous scanning)
    
    // Calibration Offsets (Remote Configured)
    float tempOffsetWired = 0.0f;
    float tempOffsetBle = 0.0f;
    
    // Metadata
    int configVersion = 0;
};

// === LOGGING BUFFER ===
// Simple ring buffer-like structure to hold logs during wakeup
struct LogEntry {
    char level[10]; // "info", "warn", "error"
    char code[20];  // "BLE_FAIL", "WIFI_RETRY"
    char msg[64];   // Short message
};

class LogBuffer {
    LogEntry entries[5];
    int count = 0;
public:
    void add(const char* level, const char* code, const char* msg) {
        if (count < 5) {
            strncpy(entries[count].level, level, 9);
            strncpy(entries[count].code, code, 19);
            strncpy(entries[count].msg, msg, 63);
            count++;
        }
        Serial.printf("[%s] %s: %s\n", level, code, msg);
    }
    
    int getCount() { return count; }
    LogEntry* get(int i) { return &entries[i]; }
    void clear() { count = 0; }
};

// === RTC MEMORY ===
RTC_DATA_ATTR DeviceConfig deviceConfig;
RTC_DATA_ATTR bool configInitialized = false;
RTC_DATA_ATTR int bootCount = 0;
RTC_DATA_ATTR uint32_t totalErrors = 0;
RTC_DATA_ATTR uint32_t totalSuccess = 0;

// === GLOBALS ===
struct TelemetryData {
    float tempWired = -127.0f;
    float tempBle   = -127.0f;
    float humidity  = -1.0f; 
    int   battery   = -1;
    int   rssi      = -100;
    bool  bleFound  = false;
};

TelemetryData _data;
LogBuffer _logs;
OneWire* _oneWire = nullptr;
DallasTemperature* _sensors = nullptr;

// === INITIALISEREN (Eerste boot) ===
void initializeConfig() {
    if (!configInitialized) {
        // Gebruik defaults uit config.h
        deviceConfig.sleepDuration = SLEEP_DURATION;
        deviceConfig.wifiTimeout = WIFI_TIMEOUT_MS;
        deviceConfig.watchdogTimeout = WATCHDOG_TIMEOUT;
        deviceConfig.scanDuration = 3; // 3 seconds per try
        deviceConfig.pinDS18B20 = PIN_DS18B20;
        
        // 100% Duty Cycle
        deviceConfig.bleScanInterval = 100;
        deviceConfig.bleScanWindow = 100;
        
        deviceConfig.tempOffsetWired = 0.0f;
        deviceConfig.tempOffsetBle = 0.0f;
        deviceConfig.configVersion = 0;
        
        configInitialized = true;
        _logs.add("info", "BOOT_INIT", "Config initialized with defaults");
    } else {
        Serial.printf("[RTC] Config loaded (v%d)\n", deviceConfig.configVersion);
    }
}

// === BLE CALLBACK (Xiaomi/Mijia Sensors) ===
class MyBLECallbacks : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        String foundMac = advertisedDevice.getAddress().toString();
        String targetMac = String(BLE_SENSOR_MAC);
        
        foundMac.toLowerCase();
        targetMac.toLowerCase();
        
        if (foundMac == targetMac) {
            String raw = advertisedDevice.getServiceData();
             // Some LYWSD03MMC firmware versions broadcast different lengths
             // This checks for the typical custom firmware format
            if (raw.length() >= 11) {
                uint8_t* p = (uint8_t*)raw.c_str();
                _data.battery  = p[4];
                _data.tempBle  = ((p[7] << 8) | p[6]) / 100.0f;
                _data.humidity = ((p[10] << 8) | p[9]) / 100.0f;
                _data.rssi     = advertisedDevice.getRSSI();
                _data.bleFound = true;
                advertisedDevice.getScan()->stop();
            }
        }
    }
};

// === ROBUST BLE SCAN ===
void acquireBLEData() {
    // Retry Loop (3 attempts)
    for (int attempt = 1; attempt <= 3; attempt++) {
        Serial.printf("[BLE] Scan Attempt %d/3\n", attempt);
        
        // Stack Reset (Clean Slate)
        BLEDevice::init("");
        BLEScan* pScan = BLEDevice::getScan();
        MyBLECallbacks* callbacks = new MyBLECallbacks();
        
        pScan->setAdvertisedDeviceCallbacks(callbacks, true);
        pScan->setActiveScan(true); // Active scan requests more data
        pScan->setInterval(deviceConfig.bleScanInterval);
        pScan->setWindow(deviceConfig.bleScanWindow); // 100% Duty Cycle!
        
        pScan->start(deviceConfig.scanDuration, false);
        
        pScan->clearResults();
        delete callbacks;
        BLEDevice::deinit(true); // Full de-init to reset controller
        delay(100); 

        if (_data.bleFound) {
            // Apply Calibration
            _data.tempBle += deviceConfig.tempOffsetBle;
            
            // Sanity Check
            if (_data.tempBle < -40.0 || _data.tempBle > 80.0 || _data.humidity > 100.0) {
                _logs.add("warn", "BLE_SANITY", "Invalid values detected");
                // Don't discard, just warn (could be extreme environment)
            } else {
                Serial.printf("[BLE] Success: %.2f C (Offset %.1f)\n", 
                              _data.tempBle, deviceConfig.tempOffsetBle);
                return; // Stop trying
            }
            break; 
        } else {
            // Wait slightly before retry
            delay(500);
        }
    }
    
    if (!_data.bleFound) {
        _logs.add("error", "BLE_TIMEOUT", "Sensor not found after 3 attempts");
    }
}

// === Wired Sensor (DS18B20) ===
void acquireWiredData() {
    if (_oneWire != nullptr) { delete _sensors; delete _oneWire; }
    
    _oneWire = new OneWire(deviceConfig.pinDS18B20);
    _sensors = new DallasTemperature(_oneWire);
    _sensors->begin();
    delay(200);
    
    if (_sensors->getDeviceCount() == 0) {
        _logs.add("error", "WIRE_MISSING", "No DS18B20 detected");
        return;
    }
    
    _sensors->requestTemperatures();
    delay(200);
    
    float t = _sensors->getTempCByIndex(0);
    
    if (t > -50.0f && t < 120.0f) {
        // Apply Calibration
        _data.tempWired = t + deviceConfig.tempOffsetWired;
        Serial.printf("[WIRE] %.2f C (Offset %.1f)\n", 
                      _data.tempWired, deviceConfig.tempOffsetWired);
    } else {
        _logs.add("error", "WIRE_INVALID", "Reading out of range");
    }
}

// === STAP 3: WiFi & Convex (Remote Config) ===
void sendToConvex() {
    Serial.print(F("[WIFI] Connecting"));
    
    WiFi.mode(WIFI_STA);
    
    // Debug: Print actual MAC address
    Serial.println();
    Serial.print(F("[DEBUG] MAC Address: "));
    Serial.println(WiFi.macAddress());
    Serial.print(F("[DEBUG] Expected: "));
    Serial.println(ESP32_DEVICE_MAC);
    
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    
    // Max Power for robustness
    WiFi.setTxPower(WIFI_POWER_19_5dBm);

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && (millis() - start) < 30000) {  // 30 sec timeout
        delay(500);
        Serial.print(".");
    }

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println(F("\n[WIFI] Timeout"));
        totalErrors++;
        // Don't log to Convex because we can't reach it!
        return;
    }
    
    Serial.println(F("\n[WIFI] Connected. Sending..."));
    
    // Build JSON payload manually to control float precision and memory
    String json;
    json.reserve(512); // Reserve more for logs
    json = "{";
    json += "\"sensorId\":\"" + String(DEVICE_NAME) + "\",";
    json += "\"value\":" + String(_data.tempWired) + ",";
    json += "\"status\":\"ok\",";
    json += "\"signal\":" + String(_data.rssi) + ",";
    json += "\"mac\":\"" + WiFi.macAddress() + "\"";
    
    if (_data.bleFound) {
        json += ",\"tempBle\":" + String(_data.tempBle);
        json += ",\"humidity\":" + String(_data.humidity);
        json += ",\"battery\":" + String(_data.battery);
    }
    
    // Append Logs
    if (_logs.getCount() > 0) {
        json += ",\"logs\":[";
        for (int i = 0; i < _logs.getCount(); i++) {
            LogEntry* l = _logs.get(i);
            json += (i > 0 ? "," : "");
            json += "{\"level\":\"" + String(l->level) + "\",";
            json += "\"code\":\"" + String(l->code) + "\",";
            json += "\"message\":\"" + String(l->msg) + "\"}";
        }
        json += "]";
    }
    
    json += "}";
    
    Serial.println("[DEBUG] Payload: " + json);

    WiFiClientSecure* client = new WiFiClientSecure();
    HTTPClient* http = new HTTPClient();
    
    if (client && http) {
        client->setInsecure();
        
        Serial.println("[DEBUG] Connecting to: " + String(CONVEX_URL));
        
        if (http->begin(*client, CONVEX_URL)) {
            http->addHeader("Content-Type", "application/json");
            http->addHeader("X-ESP32-Secret", CONVEX_SECRET); // Capital X!
            
            Serial.println("[DEBUG] Sending POST...");
            int code = http->POST(json);
            
            if (code == 200) {
                Serial.println(F("[TX] Success"));
                totalSuccess++;
                
                // Parse config response
                String response = http->getString();
                StaticJsonDocument<768> doc; // Increased size for new config
                DeserializationError error = deserializeJson(doc, response);
                
                if (!error && doc.containsKey("config")) {
                    JsonObject config = doc["config"];
                    if (config.containsKey("sleepDuration")) deviceConfig.sleepDuration = config["sleepDuration"];
                    if (config.containsKey("scanDuration")) deviceConfig.scanDuration = config["scanDuration"];
                    if (config.containsKey("tempOffsetWired")) deviceConfig.tempOffsetWired = config["tempOffsetWired"];
                    if (config.containsKey("tempOffsetBle")) deviceConfig.tempOffsetBle = config["tempOffsetBle"];
                }
            } else if (code > 0) {
                Serial.printf("[TX] Error: HTTP %d\n", code);
                Serial.println("[DEBUG] Response: " + http->getString());
                totalErrors++;
            } else {
                Serial.printf("[TX] Connection failed: %d\n", code);
                Serial.println("[DEBUG] Possible SSL/DNS issue");
                totalErrors++;
            }
            http->end();
        } else {
            Serial.println("[TX] FATAL: Could not connect to server");
            Serial.println("[DEBUG] Check URL and SSL certificate");
        }
        delete http;
        delete client;
    }

    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
}

// === SETUP (Main Logic) ===
void setup() {
    setCpuFrequencyMhz(80);
    Serial.begin(SERIAL_BAUD);
    delay(100);
    
    // Boot count
    if (esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_UNDEFINED) {
        bootCount = 0;
        initializeConfig();
    } else {
        bootCount++;
    }

    Serial.printf("\n=== SMARTCOOL V6 (Boot #%d) ===\n", bootCount);
    
    initializeConfig(); // Ensure loaded
    
    // Acquire & Transmit
    acquireBLEData();
    acquireWiredData();
    sendToConvex();
    
    // Deep Sleep
    Serial.printf("[SLEEP] %ds\n", deviceConfig.sleepDuration);
    Serial.flush();
    esp_sleep_enable_timer_wakeup((uint64_t)deviceConfig.sleepDuration * 1000000ULL);
    esp_deep_sleep_start();
}

void loop() {}