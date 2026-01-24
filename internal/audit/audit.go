package audit

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

// EventType defines the category of the audit log.
type EventType string

const (
	EventLoginSuccess  EventType = "LOGIN_SUCCESS"
	EventLoginFailed   EventType = "LOGIN_FAILED"
	EventLogout        EventType = "LOGOUT"
	EventPasswordReset EventType = "PASSWORD_RESET"
	EventTenantSwitch  EventType = "TENANT_SWITCH"
	EventDataAccess    EventType = "DATA_ACCESS" // High volume, critical for compliance
	EventConfigChange  EventType = "CONFIG_CHANGE"
)

// AuditLogger defines the contract for immutable logging.
type AuditLogger interface {
	Log(ctx context.Context, actorID uuid.UUID, action EventType, resource string, metadata map[string]string)
}

// JSONAuditLogger writes structured logs to stdout, but with a specific "audit" key
// that can be filtered by log aggregators (Datadog, Splunk, Sentry) to go to a separate index.
type JSONAuditLogger struct {
	logger *slog.Logger
	mu     sync.Mutex
}

func NewJSONAuditLogger() *JSONAuditLogger {
	// We use a separate handler/logger instance to ensure consistent formatting
	// independent of the main app logger.
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	return &JSONAuditLogger{
		logger: slog.New(handler),
	}
}

func (l *JSONAuditLogger) Log(ctx context.Context, actorID uuid.UUID, action EventType, resource string, metadata map[string]string) {
	// Anti-Gravity: "Compliance is Mandatory".
	// We ensure timestamps are UTC and format is strict.

	fields := []interface{}{
		slog.String("log_type", "AUDIT_TRAIL"), // Marker for aggregators
		slog.String("actor_id", actorID.String()),
		slog.String("action", string(action)),
		slog.String("resource", resource),
		slog.Time("timestamp_utc", time.Now().UTC()),
	}

	// Flatten metadata
	for k, v := range metadata {
		fields = append(fields, slog.String("meta_"+k, v))
	}

	// Extract generic context info if available (IP, UserAgent)
	// (Assuming middleware populates this, or we rely on metadata arg)

	l.logger.InfoContext(ctx, "audit_event", fields...)
}

// MockAuditLogger for testing
type MockAuditLogger struct{}

func (m *MockAuditLogger) Log(ctx context.Context, actorID uuid.UUID, action EventType, resource string, metadata map[string]string) {
	// No-op
}
