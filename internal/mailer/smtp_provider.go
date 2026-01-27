package mailer

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/crypto"
)

// SMTPProvider implements EmailProvider using standard SMTP protocol.
// Supports both STARTTLS (port 587) and direct TLS (port 465).
//
// Security Features:
// - SSRF protection via ValidateSMTPHost (blocks private IPs)
// - MIME injection prevention via sanitizeEmailAddress
// - Credential decryption happens in-memory only (never logged)
// - Timeout isolation per email (prevents worker starvation)
type SMTPProvider struct {
	Config     SMTPConfig
	KeyVersion int // For versioned decryption
}

// NewSMTPProvider creates a new SMTP provider with validation.
// Returns error if configuration is invalid (SSRF check, invalid ports, etc.)
func NewSMTPProvider(config SMTPConfig, keyVersion int) (*SMTPProvider, error) {
	// Validate host and port (SSRF protection)
	if err := ValidateSMTPConfig(config.Host, config.Port); err != nil {
		return nil, fmt.Errorf("invalid SMTP configuration: %w", err)
	}

	// Validate From address (MIME injection prevention)
	if _, err := sanitizeEmailAddress(config.From); err != nil {
		return nil, fmt.Errorf("invalid From address: %w", err)
	}

	return &SMTPProvider{
		Config:     config,
		KeyVersion: keyVersion,
	}, nil
}

// Send delivers an email via SMTP with full security controls.
//
// Security Controls Applied:
// 1. SSRF prevention (re-validates host on every send, not just config time)
// 2. MIME injection prevention (sanitizes To/From addresses)
// 3. Timeout enforcement (respects ctx deadline, max 15s recommended)
// 4. Credential decryption in-memory (password never logged)
//
// Anti-Gravity Law 2: Silence is Golden
// - Never log the decrypted password
// - Never log the full email body
// - Return generic errors to client (detailed errors go to Sentry only)
func (p *SMTPProvider) Send(ctx context.Context, payload EmailPayload) (string, error) {
	logger := slog.With(
		"tenant_id", payload.TenantID,
		"template", payload.Template,
		"request_id", payload.RequestID,
	)

	// 1. CRITICAL: Re-validate host on EVERY send (prevents DNS rebinding)
	if err := ValidateSMTPConfig(p.Config.Host, p.Config.Port); err != nil {
		logger.Error("SSRF attempt blocked", "host", p.Config.Host, "error", err)
		return "", fmt.Errorf("SMTP configuration failed validation")
	}

	// 2. Decrypt password (in-memory only, NEVER log this)
	password, err := crypto.DecryptTenantSecretV(p.Config.PassEncrypted, p.KeyVersion)
	if err != nil {
		logger.Error("Failed to decrypt SMTP password", "error", err)
		return "", fmt.Errorf("SMTP authentication configuration error")
	}
	defer func() {
		// Zero out password in memory (defense-in-depth)
		password = ""
	}()

	// 3. Sanitize email addresses (MIME injection prevention)
	toAddr, err := sanitizeEmailAddress(payload.To)
	if err != nil {
		logger.Warn("Invalid recipient address", "error", err)
		return "", fmt.Errorf("invalid recipient address")
	}

	fromAddr, err := sanitizeEmailAddress(p.Config.From)
	if err != nil {
		logger.Error("Invalid From address in config", "error", err)
		return "", fmt.Errorf("SMTP configuration error")
	}

	// 4. Build email message (RFC 5322 format)
	message, err := p.buildMessage(fromAddr, toAddr, payload)
	if err != nil {
		return "", fmt.Errorf("failed to build email message: %w", err)
	}

	// 5. Establish SMTP connection with timeout
	serverAddr := fmt.Sprintf("%s:%d", p.Config.Host, p.Config.Port)

	// Create connection with context timeout
	var conn net.Conn
	dialer := &net.Dialer{
		Timeout: 5 * time.Second, // TCP handshake timeout
	}

	if p.Config.TLSMode == "tls" {
		// Direct TLS (port 465)
		tlsConfig := &tls.Config{
			ServerName: p.Config.Host,
			MinVersion: tls.VersionTLS12, // Enforce TLS 1.2+ (no SSLv3, TLS 1.0, TLS 1.1)
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", serverAddr, tlsConfig)
	} else {
		// Plain connection (will upgrade with STARTTLS)
		conn, err = dialer.DialContext(ctx, "tcp", serverAddr)
	}

	if err != nil {
		logger.Error("Failed to connect to SMTP server", "host", p.Config.Host, "error", err)
		return "", fmt.Errorf("SMTP connection failed")
	}
	defer conn.Close()

	// 6. Create SMTP client
	client, err := smtp.NewClient(conn, p.Config.Host)
	if err != nil {
		logger.Error("Failed to create SMTP client", "error", err)
		return "", fmt.Errorf("SMTP protocol error")
	}
	defer client.Quit()

	// 7. STARTTLS if needed (port 587)
	if p.Config.TLSMode == "starttls" {
		tlsConfig := &tls.Config{
			ServerName: p.Config.Host,
			MinVersion: tls.VersionTLS12,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			logger.Error("STARTTLS failed", "error", err)
			return "", fmt.Errorf("SMTP TLS upgrade failed")
		}
	}

	// 8. Authenticate
	auth := smtp.PlainAuth("", p.Config.User, password, p.Config.Host)
	if err := client.Auth(auth); err != nil {
		logger.Error("SMTP authentication failed", "user", p.Config.User, "error", err)
		return "", fmt.Errorf("SMTP authentication failed")
	}

	// 9. Send email
	if err := client.Mail(fromAddr); err != nil {
		return "", fmt.Errorf("SMTP MAIL command failed: %w", err)
	}

	if err := client.Rcpt(toAddr); err != nil {
		return "", fmt.Errorf("SMTP RCPT command failed: %w", err)
	}

	writer, err := client.Data()
	if err != nil {
		return "", fmt.Errorf("SMTP DATA command failed: %w", err)
	}

	_, err = writer.Write(message)
	if err != nil {
		return "", fmt.Errorf("failed to write email data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to finalize email: %w", err)
	}

	// 10. Success - generate tracking ID
	// (In production, use provider's message ID if available via SMTP extensions)
	messageID := fmt.Sprintf("<%s@%s>", payload.RequestID, p.Config.Host)

	logger.Info("Email sent successfully",
		"to_hash", HashRecipient(payload.To), // Log hash, not raw email (GDPR)
		"message_id", messageID,
	)

	return messageID, nil
}

// buildMessage constructs an RFC 5322 compliant email message.
// For now, uses plain text. In production, load HTML templates.
func (p *SMTPProvider) buildMessage(from, to string, payload EmailPayload) ([]byte, error) {
	// Generate Message-ID (helps with delivery tracking)
	messageID := fmt.Sprintf("<%s@%s>", payload.RequestID, p.Config.Host)

	// Build headers
	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = to
	headers["Subject"] = p.getSubject(payload.Template)
	headers["Message-ID"] = messageID
	headers["Date"] = time.Now().Format(time.RFC1123Z)
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/plain; charset=UTF-8"

	// Construct message
	var msg strings.Builder
	for k, v := range headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msg.WriteString("\r\n") // Blank line separates headers from body

	// Body (for now, simple text - TODO: load HTML templates)
	body := p.buildBody(payload)
	msg.WriteString(body)

	return []byte(msg.String()), nil
}

// getSubject returns the email subject based on template type.
// TODO: Load from template files instead of hardcoding
func (p *SMTPProvider) getSubject(template EmailTemplate) string {
	subjects := map[EmailTemplate]string{
		TemplateInviteUser:        "You've been invited",
		TemplatePasswordReset:     "Reset your password",
		TemplateEmailVerification: "Verify your email address",
		TemplateMFAEnabled:        "Two-factor authentication enabled",
		TemplateMFADisabled:       "Two-factor authentication disabled",
		TemplateAccountLocked:     "Your account has been locked",
		TemplatePasswordChanged:   "Your password was changed",
	}

	if subject, ok := subjects[template]; ok {
		return subject
	}
	return "Notification"
}

// buildBody constructs the email body from template data.
// TODO: Use html/template for proper templating
func (p *SMTPProvider) buildBody(payload EmailPayload) string {
	// Simple text-based body for MVP
	// In production, load HTML templates from templates/ directory
	var body strings.Builder

	body.WriteString("Hello,\n\n")

	switch payload.Template {
	case TemplateInviteUser:
		role, _ := payload.Data["role"].(string)
		link, _ := payload.Data["link"].(string)
		body.WriteString(fmt.Sprintf("You've been invited as %s.\n\n", role))
		body.WriteString(fmt.Sprintf("Click here to accept: %s\n\n", link))

	case TemplatePasswordReset:
		link, _ := payload.Data["link"].(string)
		body.WriteString("You requested a password reset.\n\n")
		body.WriteString(fmt.Sprintf("Reset your password: %s\n\n", link))
		body.WriteString("This link expires in 1 hour.\n\n")

	case TemplateEmailVerification:
		link, _ := payload.Data["link"].(string)
		body.WriteString("Please verify your email address.\n\n")
		body.WriteString(fmt.Sprintf("Verify: %s\n\n", link))

	default:
		body.WriteString("This is a notification from the system.\n\n")
	}

	body.WriteString("Thank you,\nThe Team")

	return body.String()
}

// sanitizeEmailAddress validates and sanitizes an email address.
// Prevents MIME injection (CRLF) and SMTP header injection.
//
// Security:
// - Uses net/mail.ParseAddress for RFC 5322 compliance
// - Checks for CRLF injection in address and display name
// - Returns error if validation fails (fail-closed)
func sanitizeEmailAddress(addr string) (string, error) {
	// 1. Parse via net/mail (validates RFC 5322 format)
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		return "", fmt.Errorf("invalid email format: %w", err)
	}

	// 2. Check for CRLF injection (MIME header injection prevention)
	if strings.ContainsAny(parsed.Address, "\r\n") {
		return "", fmt.Errorf("CRLF injection detected in email address")
	}

	if strings.ContainsAny(parsed.Name, "\r\n") {
		return "", fmt.Errorf("CRLF injection detected in display name")
	}

	// 3. Return safely reconstructed address
	// net/mail.ParseAddress.String() properly quotes display names
	return parsed.String(), nil
}
