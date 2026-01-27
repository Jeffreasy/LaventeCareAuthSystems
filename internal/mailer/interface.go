// Package mailer provides email sending functionality with multi-tenant support.
// Implements SSRF protection, rate limiting, and async queue processing.
package mailer

import (
	"context"

	"github.com/google/uuid"
)

// EmailProvider defines the contract for transactional email delivery.
// Implementations MUST be:
// - Thread-safe (supports concurrent sends)
// - Idempotent (retry-safe, same payload → same result)
// - Observable (returns tracking metadata for audit logging)
//
// Security Requirements:
// - Validate all inputs before constructing SMTP message (Law 1: Input is Toxic)
// - Never log passwords or decrypted credentials (Law 2: Silence is Golden)
// - Implement egress filtering to prevent SSRF (Law 3: Infrastructure is a Fortress)
type EmailProvider interface {
	// Send delivers an email and returns the provider's message ID for tracking.
	// Returns error if validation fails, SMTP connection fails, or delivery is rejected.
	//
	// Context:
	// - ctx should have timeout (recommended: 15s max to prevent worker starvation)
	// - ctx.Done() should be checked to handle cancellation gracefully
	Send(ctx context.Context, payload EmailPayload) (providerMessageID string, err error)
}

// EmailPayload encapsulates all data required for sending an email.
// ALL fields are validated in the Business Logic layer BEFORE calling Send().
//
// Validation Checklist:
// - To: Must pass net/mail.ParseAddress (prevents SMTP header injection)
// - TenantID: Must be valid UUID (enforces Multi-Tenant isolation)
// - Template: Must be in ValidTemplates map (prevents path traversal)
// - Data: Must be pre-sanitized (no raw user input in template variables)
type EmailPayload struct {
	// Recipient email address (MUST be validated via net/mail.ParseAddress)
	To string `json:"to"`

	// Tenant context (for rate limiting, audit logging, and SMTP config lookup)
	TenantID uuid.UUID `json:"tenant_id"`

	// Template name (restricts to whitelisted templates, prevents injection)
	Template EmailTemplate `json:"template"`

	// Template data (MUST be pre-sanitized, use DTOs not raw DB models)
	// Example: {"UserName": "John", "InviteLink": "https://..."}
	Data map[string]any `json:"data"`

	// Request ID for distributed tracing (Sentry correlation)
	RequestID string `json:"request_id"`
}

// EmailTemplate is an enum to prevent arbitrary template path injection.
// Only these templates are allowed. Adding a new template requires code change
// (intentional - forces security review).
type EmailTemplate string

const (
	TemplateInviteUser        EmailTemplate = "invite_user"
	TemplatePasswordReset     EmailTemplate = "password_reset"
	TemplateEmailVerification EmailTemplate = "email_verification"
	TemplateMFAEnabled        EmailTemplate = "mfa_enabled"
	TemplateMFADisabled       EmailTemplate = "mfa_disabled"
	TemplateAccountLocked     EmailTemplate = "account_locked"
	TemplatePasswordChanged   EmailTemplate = "password_changed"
)

// ValidTemplates is a set of allowed templates for runtime validation.
// Check this before calling Send() to prevent unauthorized template usage.
var ValidTemplates = map[EmailTemplate]bool{
	TemplateInviteUser:        true,
	TemplatePasswordReset:     true,
	TemplateEmailVerification: true,
	TemplateMFAEnabled:        true,
	TemplateMFADisabled:       true,
	TemplateAccountLocked:     true,
	TemplatePasswordChanged:   true,
}

// SMTPConfig holds tenant-specific SMTP configuration.
// This is loaded from tenants.mail_config JSONB column.
//
// Security Notes:
// - PassEncrypted MUST be decrypted via crypto.DecryptTenantSecretV before use
// - Host and Port MUST be validated via ValidateSMTPHost/Port (SSRF protection)
// - From MUST be validated via net/mail.ParseAddress (MIME injection prevention)
type SMTPConfig struct {
	Host          string `json:"host"`           // e.g., "smtp.office365.com"
	Port          int    `json:"port"`           // e.g., 587
	User          string `json:"user"`           // e.g., "noreply@tenant.nl"
	PassEncrypted string `json:"pass_encrypted"` // AES-256-GCM encrypted password
	From          string `json:"from"`           // e.g., "Tenant Name <noreply@tenant.nl>"
	TLSMode       string `json:"tls_mode"`       // "starttls" or "tls"
}
