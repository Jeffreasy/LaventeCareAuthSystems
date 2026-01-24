package auth

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"image/png"
	"math/big"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	ErrMFANotEnabled = errors.New("mfa not enabled for user")
	ErrInvalidCode   = errors.New("invalid mfa code")
)

// MFAService handles TOTP generation and validation.
type MFAService struct {
	issuer string
}

func NewMFAService(issuer string) *MFAService {
	return &MFAService{
		issuer: issuer,
	}
}

// GenerateSecret creates a new TOTP secret and returns the key and a PNG QR code.
func (s *MFAService) GenerateSecret(accountName string) (*otp.Key, []byte, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: accountName,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate totp key: %w", err)
	}

	// Convert to PNG for display
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create qr code: %w", err)
	}

	if err := png.Encode(&buf, img); err != nil {
		return nil, nil, fmt.Errorf("failed to encode png: %w", err)
	}

	return key, buf.Bytes(), nil
}

// ValidateCode checks if the provided code is valid for the given secret.
// We allow a small skew (1 period) for clock drift.
func (s *MFAService) ValidateCode(code string, secret string) bool {
	valid := totp.Validate(code, secret)
	return valid
}

// GenerateBackupCodes creates cryptographically secure recovery codes.
// Returns the raw codes. Caller is responsible for hashing them before storage.
// Format: XXXX-XXXX (8 chars, Base32-ish for readability, no I/O/0/1 confusion)
func (s *MFAService) GenerateBackupCodes(count int) ([]string, error) {
	// Base32-ish charset: excludes I, O, 0, 1 for visual clarity
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	codes := make([]string, count)

	for i := 0; i < count; i++ {
		code := make([]byte, 8) // 8 characters total
		for j := 0; j < 8; j++ {
			// crypto/rand is imported at package level
			num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			if err != nil {
				return nil, fmt.Errorf("crypto/rand failed: %w", err)
			}
			code[j] = chars[num.Int64()]
		}
		// Format: XXXX-XXXX for better UX
		codes[i] = string(code[:4]) + "-" + string(code[4:])
	}
	return codes, nil
}

// GenerateCode (Helper for testing/dev)
func (s *MFAService) GenerateCode(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}
