package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrInvalidResetToken = errors.New("invalid or expired reset token")
)

// GenerateSecureToken creates a random string for reference tokens.
func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// hashToken uses SHA256 for deterministic token lookup.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// RequestPasswordReset initiates the flow.
func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	// 1. Find User (Silence is Golden: if not found, pretend success)
	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		// Log internal, return nil to client
		return nil
	}

	appURL := s.config.DefaultAppURL // Config-based fallback
	if appURL == "" {
		appURL = "https://auth.laventecare.nl" // Ultimate fallback if config not set
	}
	if user.DefaultTenantID.Valid {
		// Fetch Tenant Config for App URL
		// Note: This requires the new GetTenantConfig query to be generated.
		// If valid, use it.
		// We use a detached context or same context? Same context.
		tenantConfig, err := s.queries.GetTenantConfig(ctx, user.DefaultTenantID)
		if err == nil && tenantConfig.AppUrl != "" {
			appURL = tenantConfig.AppUrl
		}
	}

	// 2. Generate Token
	token, err := GenerateSecureToken(32)
	if err != nil {
		return err
	}

	// 3. Hash Token (SHA256 for lookup)
	tokenHash := hashToken(token)

	// 4. Store in DB
	// Type "password_reset", Expiry 15 mins
	_, err = s.queries.CreateVerificationToken(ctx, db.CreateVerificationTokenParams{
		UserID:    user.ID,
		TokenHash: tokenHash,
		Type:      "password_reset",
		TenantID:  pgtype.UUID{Valid: false}, // System level action
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(15 * time.Minute), Valid: true},
	})
	if err != nil {
		return err
	}

	// 6. Send Email
	// We send the RAW token. DB stores the HASH.
	return s.mail.SendPasswordReset(ctx, email, token, appURL)
}

// ResetPassword completes the flow.
func (s *AuthService) ResetPassword(ctx context.Context, rawToken string, newPassword string) error {
	hashedToken := hashToken(rawToken) // Deterministic

	// 2. Lookup
	storedToken, err := s.queries.GetVerificationToken(ctx, hashedToken)
	if err != nil {
		return ErrInvalidResetToken
	}

	// 3. Check Expiry
	if time.Now().After(storedToken.ExpiresAt.Time) {
		s.queries.DeleteVerificationToken(ctx, storedToken.ID) // Cleanup
		return ErrInvalidResetToken
	}

	// 4. Update Password
	newHash, err := s.passwordHasher.Hash(newPassword)
	if err != nil {
		return err
	}

	_, err = s.queries.UpdateUserPassword(ctx, db.UpdateUserPasswordParams{
		ID:           storedToken.UserID,
		PasswordHash: pgtype.Text{String: newHash, Valid: true},
	})
	if err != nil {
		return err
	}

	// 5. Consume Token (One-Time Use)
	return s.queries.DeleteVerificationToken(ctx, storedToken.ID)
}

// RequestEmailVerification initiates the email verification flow.
func (s *AuthService) RequestEmailVerification(ctx context.Context, email string) error {
	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return nil // Silence is Golden
	}

	if user.IsEmailVerified {
		return nil // Already verified, do nothing (or send "already verified" email)
	}

	token, err := GenerateSecureToken(32)
	if err != nil {
		return err
	}

	tokenHash := hashToken(token)

	_, err = s.queries.CreateVerificationToken(ctx, db.CreateVerificationTokenParams{
		UserID:    user.ID,
		TokenHash: tokenHash,
		Type:      "email_verify",
		TenantID:  pgtype.UUID{Valid: false},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true}, // Longer expiry for welcome emails
	})
	if err != nil {
		return err
	}

	appURL := s.config.DefaultAppURL
	if appURL == "" {
		appURL = "https://auth.laventecare.nl"
	}
	if user.DefaultTenantID.Valid {
		tenantConfig, err := s.queries.GetTenantConfig(ctx, user.DefaultTenantID)
		if err == nil && tenantConfig.AppUrl != "" {
			appURL = tenantConfig.AppUrl
		}
	}

	return s.mail.SendVerification(ctx, email, token, appURL)
}

// VerifyEmail completes the email verification flow.
func (s *AuthService) VerifyEmail(ctx context.Context, rawToken string) error {
	hashedToken := hashToken(rawToken)

	storedToken, err := s.queries.GetVerificationToken(ctx, hashedToken)
	if err != nil {
		return ErrInvalidResetToken // Reuse error or create specific ErrInvalidVerificationToken
	}

	if time.Now().After(storedToken.ExpiresAt.Time) {
		s.queries.DeleteVerificationToken(ctx, storedToken.ID)
		return ErrInvalidResetToken
	}

	// Verify User
	_, err = s.queries.VerifyUserEmail(ctx, storedToken.UserID)
	if err != nil {
		return err
	}

	// Consume Token
	return s.queries.DeleteVerificationToken(ctx, storedToken.ID)
}
