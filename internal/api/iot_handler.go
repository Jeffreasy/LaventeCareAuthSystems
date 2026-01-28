package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
)

// IoTHandler manages device telemetry and authentication.
type IoTHandler struct {
	service *auth.IoTService
}

// NewIoTHandler creates a new handler for IoT devices.
func NewIoTHandler(service *auth.IoTService) *IoTHandler {
	return &IoTHandler{
		service: service,
	}
}

// HandleTelemetry accepts telemetry from ESP32, validates the device, and proxies to Convex.
func (h *IoTHandler) HandleTelemetry(w http.ResponseWriter, r *http.Request) {
	// 1. Input Validation (Anti-Gravity Law 1)
	var payload auth.TelemetryPayload // Use Service-defined struct

	if err := helpers.DecodeJSON(r, &payload); err != nil {
		slog.Warn("IoT: Decode error", "error", err)
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// 2. Authentication (Gatekeeper)
	deviceSecret := r.Header.Get("X-ESP32-Secret")
	if deviceSecret == "" {
		http.Error(w, "Missing Device Secret", http.StatusUnauthorized)
		return
	}

	// 3. Delegate to Service (Logic Core)
	convexResponse, err := h.service.ProcessTelemetry(r.Context(), deviceSecret, payload)
	if err != nil {
		slog.Warn("IoT: Processing failed", "sensor", payload.SensorID, "error", err)
		if err.Error() == "invalid device secret" || err.Error() == "convex integration not configured" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		} else {
			http.Error(w, "Telemetry processing failed", http.StatusBadGateway)
		}
		return
	}

	// 4. Return success/config
	w.WriteHeader(http.StatusOK)
	if convexResponse != nil {
		json.NewEncoder(w).Encode(convexResponse)
	} else {
		// Default response if no convex config returned (though service always returns it or error)
		w.Write([]byte(`{"status":"ok"}`))
	}
}
