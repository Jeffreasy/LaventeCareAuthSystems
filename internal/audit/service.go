package audit

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// AuditService defines the interface for recording security events.
type AuditService interface {
	Log(ctx context.Context, action string, params LogParams)
}

// LogParams encapsulates optional fields for an audit log.
type LogParams struct {
	ActorID   uuid.UUID
	TargetID  uuid.UUID
	TenantID  uuid.UUID
	SessionID uuid.UUID
	Metadata  map[string]interface{}
}

// DBLogger implements AuditService using the PostgreSQL database.
type DBLogger struct {
	queries *db.Queries
	logger  *slog.Logger
}

func NewDBLogger(queries *db.Queries, logger *slog.Logger) *DBLogger {
	return &DBLogger{
		queries: queries,
		logger:  logger,
	}
}

// Log records an event.
// Design Decision: We execute purely synchronously for CRITICAL events for now (MVP).
// In high-scale, this should push to a channel/queue.
func (s *DBLogger) Log(ctx context.Context, action string, params LogParams) {
	// 1. Extract Request Context (IP, UserAgent, RequestID)
	// This relies on Middleware populating the context?
	// Or we require params to pass them?
	// Decision: Extract from Context if available, else generic.
	// But `audit` package shouldn't depend on `middleware` package to avoid cycles.
	// We will rely on simple context keys or generic value extraction if keys were exported in a shared `pkg/context` or similar.
	// For now, we will assume params are passed or extracted here if we decide to move keys to shared pkg.
	// Actually, `middleware.GetIP(ctx)` would be circular if middleware imports audit.
	// Let's keep it simple: We won't deep-inspect context here. We assume context has what we need OR we just log what we have.
	// Wait, we need IP/UA/ReqID.
	// We'll define keys in specific package or just assume they are not here for MVP unless added to params.
	// Refined: We will add IP/UA/ReqID to LogParams for explicit passing to avoid "Magic Context".

	metadataBytes, err := json.Marshal(params.Metadata)
	if err != nil {
		s.logger.Error("audit_metadata_marshal_failed", "error", err)
		metadataBytes = []byte("{}")
	}

	// Helper to convert UUID to pgtype or Null
	toUUID := func(u uuid.UUID) pgtype.UUID {
		return pgtype.UUID{Bytes: u, Valid: u != uuid.Nil}
	}

	// Get IP/Info from context?
	// We'll implement a `ExtractContextInfo` helper if we move keys to `pkg`.
	// For now, we omit IP/UA unless passed.

	err = s.queries.CreateAuditLog(ctx, db.CreateAuditLogParams{
		ActorID:   toUUID(params.ActorID),
		SessionID: toUUID(params.SessionID),
		TenantID:  toUUID(params.TenantID),
		Action:    action,
		TargetID:  toUUID(params.TargetID),
		Metadata:  metadataBytes,
		// IpAddress: ... (Need to add to Params or Context)
		// UserAgent: ...
		// RequestId: ...
	})

	if err != nil {
		// Fallback: Log to Stdout so we don't lose the event entirely
		s.logger.Error("audit_db_insert_failed",
			"action", action,
			"error", err,
			"actor", params.ActorID,
		)
	}
}
