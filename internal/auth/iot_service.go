package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

// IoTService handles device logic.
type IoTService struct {
	queries    *db.Queries
	httpClient *http.Client
	config     IoTConfig
}

// IoTConfig holds dependencies for IoT operations.
type IoTConfig struct {
	ConvexURL       string
	ConvexDeployKey string
}

func NewIoTService(queries *db.Queries, config IoTConfig) *IoTService {
	return &IoTService{
		queries: queries,
		config:  config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// TelemetryPayload matches the incoming ESP32 data structure.
type TelemetryPayload struct {
	SensorID string          `json:"sensorId"`
	Value    float64         `json:"value"`
	Status   string          `json:"status"`
	Signal   int             `json:"signal"`
	Mac      string          `json:"mac"`
	TempBle  *float64        `json:"tempBle,omitempty"`
	Humidity *float64        `json:"humidity,omitempty"`
	Battery  *int            `json:"battery,omitempty"`
	Logs     interface{}     `json:"logs,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// ProcessTelemetry authenticates the device and forwards data to Convex.
// Returns the Convex response (config) or error.
func (s *IoTService) ProcessTelemetry(ctx context.Context, secret string, payload TelemetryPayload) (interface{}, error) {
	// 1. Authenticate Device
	// Using background context for DB to avoid strict RLS if it's a device lookup?
	// No, use passed context, assuming it's safe.
	device, err := s.queries.GetIoTDeviceByHardwareID(ctx, payload.SensorID)
	if err != nil {
		return nil, fmt.Errorf("device lookup failed: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(device.SecretHash), []byte(secret)); err != nil {
		return nil, fmt.Errorf("invalid device secret")
	}

	// 2. Heartbeat (Fire & Forget)
	go func() {
		_ = s.queries.UpdateIoTDeviceHeartbeat(context.Background(), device.ID)
	}()

	// 3. Prepare Convex Payload
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

	// 4. Forward to Convex
	if s.config.ConvexURL == "" {
		return nil, fmt.Errorf("convex integration not configured")
	}

	jsonBody, _ := json.Marshal(enrichedPayload)
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.ConvexURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create convex request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if s.config.ConvexDeployKey != "" {
		req.Header.Set("X-Convex-Deploy-Key", s.config.ConvexDeployKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("convex request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("convex error %d: %s", resp.StatusCode, string(body))
	}

	// 5. Parse Response
	var convexResponse interface{}
	if err := json.NewDecoder(resp.Body).Decode(&convexResponse); err != nil {
		// Log but return partial success? No, strict service returns error.
		return nil, fmt.Errorf("convex response parse error: %w", err)
	}

	return convexResponse, nil
}

// uuidFromPg helper (duplicated from handler, but belongs in utils technically)
func uuidFromPg(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", id.Bytes[0:4], id.Bytes[4:6], id.Bytes[6:8], id.Bytes[8:10], id.Bytes[10:16])
}
