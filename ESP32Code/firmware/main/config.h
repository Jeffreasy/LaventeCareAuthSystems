#ifndef CONFIG_H
#define CONFIG_H

// =========================================================
//  STAP 1: KIES HIER JE APPARAAT
// =========================================================

// #define USE_KOELKAST_A
// #define USE_KOELKAST_B
// #define USE_KOELKAST_C
#define USE_KOELKAST_D

// =========================================================
//  HARDWARE VALIDATIE (Safety Check)
// =========================================================

#ifdef USE_KOELKAST_A
    #define DEVICE_NAME         "Koelkast_A"
    #define ESP32_DEVICE_MAC    "68:25:dd:f3:1a:80"  // ESP32 WiFi MAC
    #define BLE_SENSOR_MAC      "a4:c1:38:c8:92:5a"  // ESP1
    #define PIN_DS18B20         4   // CH340 board
#endif

#ifdef USE_KOELKAST_B
    #define DEVICE_NAME         "Koelkast_B"
    #define ESP32_DEVICE_MAC    "14:33:5c:38:28:fc"  // ESP32 WiFi MAC
    #define BLE_SENSOR_MAC      "a4:c1:38:e3:4d:72"  // ESP2
    #define PIN_DS18B20         4   // CH340 board
#endif

#ifdef USE_KOELKAST_C
    #define DEVICE_NAME         "Koelkast_C"
    #define ESP32_DEVICE_MAC    "08:3a:f2:7c:d5:00"  // ESP32 WiFi MAC
    #define BLE_SENSOR_MAC      "a4:c1:38:c8:92:5a"  // ESP3
    #define PIN_DS18B20         17  // WeMos D1 R32
#endif

#ifdef USE_KOELKAST_D
    #define DEVICE_NAME         "Koelkast_D"
    #define ESP32_DEVICE_MAC    "a4:c1:38:ae:94:ec"  // ESP32 WiFi MAC (NEEDS UPDATE!)
    #define BLE_SENSOR_MAC      "a4:c1:38:ae:94:ec"  // ESP4
    #define PIN_DS18B20         17  // WeMos D1 R32
#endif

#ifndef DEVICE_NAME
    #error "Fout: Kies een apparaat bovenaan in config.h!"
#endif

// =========================================================
//  NETWERK & BACKEND
// =========================================================

#include "secrets.h"

#ifndef WIFI_SSID
    #error "WIFI_SSID niet gedefinieerd in secrets.h"
#endif

// URL van je Convex HTTP Action (eindigend op /ingestSensorData)
#define CONVEX_URL          "https://laventecareauthsystems.onrender.com/api/v1/iot/telemetry"
// CONVEX_SECRET wordt nu geladen uit secrets.h 

// =========================================================
//  SYSTEEM DEFAULTS (Gebruikt als Remote Config faalt)
// =========================================================

#define SERIAL_BAUD         115200
#define SLEEP_DURATION      300     // Standaard 5 minuten
#define WIFI_TIMEOUT_MS     15000   // 15 sec max verbindingstijd
#define WATCHDOG_TIMEOUT    30      // 30 sec voor hard reset
#define SCAN_DURATION       10      // BLE Scan tijd in seconden

#endif