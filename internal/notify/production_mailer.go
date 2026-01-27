package notify

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/mailer"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ProductionMailer implements EmailSender using the async queue pattern.
// Emails are enqueued to the database and processed by a background worker.
//
// This implementation is:
// - Fast (<50ms, non-blocking)
// - Reliable (retry logic via worker)
// - Observable (audit logs in email_logs table)
type ProductionMailer struct {
	Pool     *pgxpool.Pool
	Logger   *slog.Logger
	TenantID uuid.UUID // Tenant context for this mailer instance
}

// NewProductionMailer creates a new production mailer for a specific tenant.
func NewProductionMailer(pool *pgxpool.Pool, logger *slog.Logger, tenantID uuid.UUID) *ProductionMailer {
	return &ProductionMailer{
		Pool:     pool,
		Logger:   logger,
		TenantID: tenantID,
	}
}

// SendInvitation enqueues an invitation email to the outbox.
// The background worker will process it asynchronously.
func (m *ProductionMailer) SendInvitation(ctx context.Context, to string, inviteURL string) error {
	payload := mailer.EmailPayload{
		To:       to,
		TenantID: m.TenantID,
		Template: mailer.TemplateInviteUser,
		Data: map[string]any{
			"link": inviteURL,
			"role": "user", // TODO: Pass role from caller
		},
		RequestID: generateRequestID(ctx),
	}

	if err := mailer.EnqueueEmail(ctx, m.Pool, payload); err != nil {
		m.Logger.Error("Failed to enqueue invitation email",
			"to_hash", mailer.HashRecipient(to),
			"error", err,
		)
		return fmt.Errorf("failed to send invitation: %w", err)
	}

	m.Logger.Info("Invitation email enqueued",
		"to_hash", mailer.HashRecipient(to),
		"tenant_id", m.TenantID,
	)

	return nil
}

// SendPasswordReset enqueues a password reset email.
func (m *ProductionMailer) SendPasswordReset(ctx context.Context, to string, token string, appURL string) error {
	resetLink := fmt.Sprintf("%s/auth/reset?token=%s", appURL, token)

	payload := mailer.EmailPayload{
		To:       to,
		TenantID: m.TenantID,
		Template: mailer.TemplatePasswordReset,
		Data: map[string]any{
			"link":  resetLink,
			"token": token, // For debugging (never logged in worker)
		},
		RequestID: generateRequestID(ctx),
	}

	if err := mailer.EnqueueEmail(ctx, m.Pool, payload); err != nil {
		m.Logger.Error("Failed to enqueue password reset email",
			"to_hash", mailer.HashRecipient(to),
			"error", err,
		)
		return fmt.Errorf("failed to send password reset: %w", err)
	}

	m.Logger.Info("Password reset email enqueued",
		"to_hash", mailer.HashRecipient(to),
	)

	return nil
}

// SendVerification enqueues an email verification email.
func (m *ProductionMailer) SendVerification(ctx context.Context, to string, token string, appURL string) error {
	verifyLink := fmt.Sprintf("%s/auth/verify?token=%s", appURL, token)

	payload := mailer.EmailPayload{
		To:       to,
		TenantID: m.TenantID,
		Template: mailer.TemplateEmailVerification,
		Data: map[string]any{
			"link":  verifyLink,
			"token": token,
		},
		RequestID: generateRequestID(ctx),
	}

	if err := mailer.EnqueueEmail(ctx, m.Pool, payload); err != nil {
		m.Logger.Error("Failed to enqueue verification email",
			"to_hash", mailer.HashRecipient(to),
			"error", err,
		)
		return fmt.Errorf("failed to send verification: %w", err)
	}

	m.Logger.Info("Verification email enqueued",
		"to_hash", mailer.HashRecipient(to),
	)

	return nil
}

// generateRequestID extracts or generates a request ID for tracing.
// In production, extract from Sentry context or generate UUID.
func generateRequestID(ctx context.Context) string {
	// TODO: Extract from Sentry trace context when integrated
	// For now, generate a simple UUID
	return uuid.New().String()
}
