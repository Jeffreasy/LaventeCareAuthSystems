package auth

import (
	"context"
	"log/slog"
)

// EmailSender defines the contract for sending transactional emails.
type EmailSender interface {
	SendPasswordReset(ctx context.Context, email string, token string, appURL string) error
	SendVerification(ctx context.Context, email string, token string, appURL string) error
}

// ConsoleEmailSender is a mock implementation that logs emails to stdout ("Anti-Gravity" dev mode).
type ConsoleEmailSender struct{}

func NewConsoleEmailSender() *ConsoleEmailSender {
	return &ConsoleEmailSender{}
}

func (s *ConsoleEmailSender) SendPasswordReset(ctx context.Context, email string, token string, appURL string) error {
	// Law 2: Silence is Golden (don't log sensitive info in production, but token needed for dev)
	link := appURL + "/reset?token=" + token
	slog.Info("📧 EMAIL SENT (MOCK)",
		"type", "password_reset",
		"to", email,
		"token", token, // Visible for dev convenience. In prod, use real provider.
		"link", link,
	)
	return nil
}

func (s *ConsoleEmailSender) SendVerification(ctx context.Context, email string, token string, appURL string) error {
	link := appURL + "/verify?token=" + token
	slog.Info("📧 EMAIL SENT (MOCK)",
		"type", "verification",
		"to", email,
		"token", token,
		"link", link,
	)
	return nil
}
