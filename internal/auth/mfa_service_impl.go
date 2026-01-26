package auth

import (
	"context"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// EnableMFA generates a secret and backup codes for the user.
type MFASetupResponse struct {
	Secret      string
	QRCode      []byte
	BackupCodes []string
}

func (s *AuthService) SetupMFA(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) (*MFASetupResponse, error) {
	user, err := s.queries.GetUserByID(ctx, db.GetUserByIDParams{
		ID:       pgtype.UUID{Bytes: userID, Valid: true},
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
	})
	if err != nil {
		return nil, ErrUserNotFound
	}

	key, img, err := s.mfaService.GenerateSecret(user.Email)
	if err != nil {
		return nil, err
	}

	// Generate 10 Backup Codes
	codes, err := s.mfaService.GenerateBackupCodes(10)
	if err != nil {
		return nil, err
	}

	return &MFASetupResponse{
		Secret:      key.Secret(),
		QRCode:      img,
		BackupCodes: codes,
	}, nil
}

// ActivateMFA confirms the setup and persists the secret + hashed backup codes.
func (s *AuthService) ActivateMFA(ctx context.Context, userID uuid.UUID, secret string, code string, backupCodes []string) error {
	// 1. Validate the TOTP code provided by the user against the NEW secret
	if !s.mfaService.ValidateCode(code, secret) {
		return ErrInvalidCode
	}

	// 2. Hash Backup Codes
	s.queries.DeleteBackupCodes(ctx, pgtype.UUID{Bytes: userID, Valid: true}) // Clear old codes if re-enabling

	for _, rawCode := range backupCodes {
		hashed := hashToken(rawCode)
		s.queries.CreateBackupCode(ctx, db.CreateBackupCodeParams{
			UserID:   pgtype.UUID{Bytes: userID, Valid: true},
			CodeHash: hashed,
		})
	}

	// 3. Enable User MFA in DB
	// 3. Enable User MFA in DB
	_, err := s.queries.UpdateUserMFA(ctx, db.UpdateUserMFAParams{
		ID:         pgtype.UUID{Bytes: userID, Valid: true},
		MfaSecret:  pgtype.Text{String: secret, Valid: true},
		MfaEnabled: true,
	})
	return err
}
