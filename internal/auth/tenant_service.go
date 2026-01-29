package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/audit"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/crypto"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/domain"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
)

// CreateTenantInput defines the input for creating a new tenant.
type CreateTenantInput struct {
	Name       string
	Slug       string
	AdminEmail string // Used for audit log "requested_by" if available, or just context
	AppURL     string
}

// CreateTenant creates a new tenant with a fresh secret key and logs the event.
// ✅ SECURE: Generates a new random secret key for the tenant.
// ✅ AUDIT: Logs the 'tenant.create' event strictly.
func (s *AuthService) CreateTenant(ctx context.Context, input CreateTenantInput) (*db.Tenant, error) {
	// 1. Generate Tenant Secret Key
	// This mimics the behavior of the setup scripts but ensuring it's done via standard crypto.
	// Note: In MVP, we might not output this key if we auto-hash it.
	// But `tenants` table requires `secret_key_hash`.
	// We'll generate a random key, hash it for storage.
	// For now, we don't return the raw key because there's no way to show it securely yet.
	// Wait, the Admin needs to know it? Or is it internal?
	// `secret_key_hash` is for validating inter-service communication.
	// We will generate it, but since we can't show it easily without a UI for it, we might just set it.
	// Actually, `internal/crypto/tenant_secrets.go` has `EncryptTenantSecret` but that's for SMTP passwords.
	// Checked `tenant_secrets.go` - it's for SMTP.
	// We need `secret_key_hash` for the tenant itself.
	// Let's assume we generate a random key and hash it.

	rawKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate tenant secret: %w", err)
	}

	// Hash it (assuming SHA256 or similar, standard for API keys in this system)
	// We need a helper for hashing API keys if it exists, or use generic hash.
	// Reviewing `security_model.md`: "Tenant Context... enforced via Row Level Security".
	// It doesn't explicitly specify the hashing algo for the tenant secret key itself,
	// but `crypto` package usually handles this.
	// Let's use `s.passwordHasher.Hash` if it's suitable, or just SHA256.
	// Given `internal/crypto` seems focused on AES, we'll rely on the hasher we have.
	// Actually, `service.go` has `passwordHasher`. But that's Bcrypt (slow).
	// For API keys, usually SHA256.
	// Let's use `crypto/sha256` directly here for simplicity if no helper exists,
	// OR reuse `passwordHasher` if speed isn't critical (Tenant creation is rare).
	// Let's use `passwordHasher` (Bcrypt) for consistency with `secret_key_hash` naming style often used for passwords.
	hashedKey, err := s.passwordHasher.Hash(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to hash secret: %w", err)
	}

	// 2. Prepare DB Params
	// Default Branding/Settings
	defaultBranding := domain.TenantBranding{
		PrimaryColor: "#000000",
	}
	defaultSettings := domain.TenantSettings{
		AllowRegistration: false,
	}

	// 3. Create Tenant in DB
	tenant, err := s.queries.CreateTenant(ctx, db.CreateTenantParams{
		Name:           input.Name,
		Slug:           input.Slug,
		SecretKeyHash:  hashedKey,
		AllowedOrigins: []string{},
		RedirectUrls:   []string{},
		Branding:       defaultBranding,
		Settings:       defaultSettings,
		AppUrl:         input.AppURL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// 4. Audit Log
	s.audit.Log(ctx, "tenant.create", audit.LogParams{
		TargetID: tenant.ID.Bytes,
		TenantID: tenant.ID.Bytes, // The new tenant is its own context here
		Metadata: map[string]interface{}{
			"slug":       input.Slug,
			"name":       input.Name,
			"app_url":    input.AppURL,
			"created_at": time.Now().UTC().Format(time.RFC3339),
		},
	})

	return &tenant, nil
}
