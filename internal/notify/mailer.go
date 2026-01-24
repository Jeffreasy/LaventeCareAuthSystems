package notify

import (
	"context"
	"log/slog"
)

type EmailSender interface {
	SendInvitation(ctx context.Context, to string, inviteURL string) error
	SendPasswordReset(ctx context.Context, to string, token string, appURL string) error
	SendVerification(ctx context.Context, to string, token string, appURL string) error
}

// DevMailer prints emails to stdout (safe for development).
type DevMailer struct {
	Logger *slog.Logger
}

func (m *DevMailer) SendInvitation(ctx context.Context, to string, inviteURL string) error {
	m.Logger.Info("📧 EMAIL SENT",
		"to", to,
		"type", "invitation",
		"url", inviteURL,
	)
	return nil
}

func (m *DevMailer) SendPasswordReset(ctx context.Context, to string, token string, appURL string) error {
	link := appURL + "/auth/reset?token=" + token
	m.Logger.Info("📧 EMAIL SENT",
		"to", to,
		"type", "password_reset",
		"token", token,
		"link", link,
	)
	return nil
}

func (m *DevMailer) SendVerification(ctx context.Context, to string, token string, appURL string) error {
	link := appURL + "/auth/verify?token=" + token
	m.Logger.Info("📧 EMAIL SENT",
		"to", to,
		"type", "verification",
		"token", token,
		"link", link,
	)
	return nil
}
