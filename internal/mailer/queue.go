package mailer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnqueueEmail writes an email to the outbox table for async processing.
// This is fast (<50ms) and non-blocking - the worker picks it up later.
//
// Security Notes:
// - Validates template before enqueueing (prevents unauthorized templates)
// - Recipient is hashed for email_logs (GDPR pseudonymization)
// - Payload is serialized as JSONB (supports complex template data)
//
// Anti-Gravity Law 1: Input is Toxic - validates payload before DB insert
// Anti-Gravity Law 3: Database is a Fortress - uses parameterized query
func EnqueueEmail(ctx context.Context, pool *pgxpool.Pool, payload EmailPayload) error {
	// 1. Validate template (prevent arbitrary template injection)
	if !ValidTemplates[payload.Template] {
		return fmt.Errorf("invalid template: %s", payload.Template)
	}

	// 2. Serialize payload to JSONB
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to serialize email payload: %w", err)
	}

	// 3. Insert into outbox (worker will pick it up)
	_, err = pool.Exec(ctx, `
		INSERT INTO email_outbox (tenant_id, payload, status, next_retry_at)
		VALUES ($1, $2, 'pending', NOW())
	`, payload.TenantID, payloadJSON)

	if err != nil {
		return fmt.Errorf("failed to enqueue email: %w", err)
	}

	return nil
}

// HashRecipient creates a SHA256 hash of an email address for GDPR-compliant logging.
// This allows duplicate detection and audit trail without storing PII.
//
// Security Notes:
// - Uses SHA256 (not MD5/SHA1 which are broken)
// - No salt needed (email addresses are already high-entropy)
// - Deterministic (same email → same hash for deduplication)
func HashRecipient(email string) string {
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])
}

// CreateEmailLog inserts an audit log entry for email delivery.
// Call this AFTER successful SMTP send (or on failure for tracking).
//
// Privacy:
// - Recipient is hashed (GDPR Art. 32 pseudonymization)
// - Email body is NEVER stored (only template type)
// - Provider message ID is stored for external tracking
func CreateEmailLog(ctx context.Context, pool *pgxpool.Pool, payload EmailPayload, status string, providerMsgID string, errorMsg string) (uuid.UUID, error) {
	recipientHash := HashRecipient(payload.To)

	var logID uuid.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO email_logs (
			tenant_id,
			recipient_hash,
			template_type,
			status,
			provider_msg_id,
			provider_error,
			created_at,
			sent_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), CASE WHEN $4 = 'sent' THEN NOW() ELSE NULL END)
		RETURNING id
	`, payload.TenantID, recipientHash, payload.Template, status, providerMsgID, errorMsg).Scan(&logID)

	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create email log: %w", err)
	}

	return logID, nil
}
