package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

// IoTHandler manages device telemetry and authentication.
type IoTHandler struct {
	queries *db.Queries
	client  *http.Client
}

// NewIoTHandler creates a new handler for IoT devices.
func NewIoTHandler(queries *db.Queries) *IoTHandler {
	return &IoTHandler{
		queries: queries,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// HandleTelemetry accepts telemetry from ESP32, validates the device, and proxies to Convex.
func (h *IoTHandler) HandleTelemetry(w http.ResponseWriter, r *http.Request) {
	// 1. Input Validation (Anti-Gravity Law 1)
	var payload struct {
		SensorID string  `json:"sensorId"`
		Value    float64 `json:"value"`
		Status   string  `json:"status"`
		Signal   int     `json:"signal"`
		// Expanded fields to match ESP32 Firmware V6
		Mac      string          `json:"mac"`
		TempBle  *float64        `json:"tempBle,omitempty"`
		Humidity *float64        `json:"humidity,omitempty"`
		Battery  *int            `json:"battery,omitempty"`
		Logs     interface{}     `json:"logs,omitempty"` // Accept any structure
		Metadata json.RawMessage `json:"metadata,omitempty"`
	}

	if err := helpers.DecodeJSON(r, &payload); err != nil {
		// Log the error for debugging
		fmt.Printf("[IoT] Decode error: %v\n", err)
		fmt.Printf("[IoT] Body: %s\n", r.Body)
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// 2. Authentication (Gatekeeper)
	// Device sends its Secret in 'X-Device-Token' header or similar.
	// For ESP32 simplified flow, we might use "X-ESP32-Secret" which maps to the device secret.
	// However, the standard plan says: "Go validates the DeviceToken in PostgreSQL."

	deviceSecret := r.Header.Get("X-ESP32-Secret")
	if deviceSecret == "" {
		http.Error(w, "Missing Device Secret", http.StatusUnauthorized)
		return
	}

	// Lookup device by Hardware ID (SensorID)
	// We need to use "storage.WithoutRLS" or ensure we have context?
	// IoT devices authenticate THEMSELVES, so we don't have a user token.
	// We run this query as "System" (background) context usually, but ensuring security.

	ctx := r.Context()
	device, err := h.queries.GetIoTDeviceByHardwareID(ctx, payload.SensorID)
	if err != nil {
		// Law 2: Silence is Golden. Don't reveal if device ID is wrong or DB error.
		// Detailed log internally.
		// h.logger.Warn("iot_auth_failed", "sensor_id", payload.SensorID, "error", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify Secret
	if err := bcrypt.CompareHashAndPassword([]byte(device.SecretHash), []byte(deviceSecret)); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 3. Heartbeat Update (Async)
	go func() {
		// Use background context to avoid cancellation if request finishes fast
		_ = h.queries.UpdateIoTDeviceHeartbeat(context.Background(), device.ID)
	}()

	// 4. Proxy to Convex
	// Enrich payload with TenantID/UserID linkage if needed, or rely on Convex knowing the device.
	// The user wants Go to "verrijk de data met de juiste TenantID en UserID".

	enrichedPayload := map[string]interface{}{
		"sensorId":  payload.SensorID,
		"value":     payload.Value,
		"status":    payload.Status,
		"signal":    payload.Signal,
		"mac":       payload.Mac,
		"tempBle":   payload.TempBle,
		"humidity":  payload.Humidity,
		"battery":   payload.Battery,
		"logs":      payload.Logs,
		"tenantId":  uuidFromPg(device.TenantID),
		"timestamp": time.Now().UnixMilli(),
	}

	convexURL := os.Getenv("CONVEX_WEBHOOK_URL")
	if convexURL == "" {
		// Fallback for testing
		convexURL = "https://dynamic-schnauzer-274.convex.site/api/gatekeeper/ingest"
	}

	deployKey := os.Getenv("CONVEX_DEPLOY_KEY")
	if deployKey == "" {
		// Log warning but continue (will fail at Convex)
		fmt.Println("[IoT] WARN: CONVEX_DEPLOY_KEY not set")
	}

	jsonBody, _ := json.Marshal(enrichedPayload)
	req, err := http.NewRequestWithContext(ctx, "POST", convexURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Printf("[IoT] Failed to create request: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Convex-Deploy-Key", deployKey)

	// Send with timeout
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[IoT] Convex request failed: %v\n", err)
		http.Error(w, "Failed to forward telemetry", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("[IoT] Convex error %d: %s\n", resp.StatusCode, string(body))
		http.Error(w, "Convex processing failed", http.StatusBadGateway)
		return
	}

	// 5. Parse Convex response and forward to ESP32
	var convexResponse struct {
		Status string `json:"status"`
		Config struct {
			SleepDuration   int     `json:"sleepDuration"`
			ScanDuration    int     `json:"scanDuration"`
			TempOffsetWired float64 `json:"tempOffsetWired"`
			TempOffsetBle   float64 `json:"tempOffsetBle"`
		} `json:"config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&convexResponse); err != nil {
		fmt.Printf("[IoT] Failed to parse Convex response: %v\n", err)
		// Still return success to ESP32, just with default config
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"config": map[string]interface{}{
				"sleepDuration":   300,
				"scanDuration":    10,
				"tempOffsetWired": 0.0,
				"tempOffsetBle":   0.0,
			},
		})
		return
	}

	// 6. Successfully forward config to ESP32
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(convexResponse)
}

// uuidFromPg converts pgtype.UUID to string for JSON
func uuidFromPg(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", id.Bytes[0:4], id.Bytes[4:6], id.Bytes[6:8], id.Bytes[8:10], id.Bytes[10:16])
}
