package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/audit"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// LoginInput defines the credentials for login.
type LoginInput struct {
	Email     string
	Password  string
	TenantID  uuid.UUID // Enforced by Anti-Gravity Law: Users are Tenant-Scoped
	IP        net.IP
	UserAgent string
}

// LoginResult contains the tokens to return to the client.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	PreAuthToken string `json:"pre_auth_token,omitempty"` // For MFA step
	User         db.User
	MfaRequired  bool `json:"mfa_required"`
}

func (s *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	// 1. Find User by Email (Strictly Scoped to Tenant)
	if input.TenantID == uuid.Nil {
		return nil, ErrTenantRequired
	}

	// 1.5 Validate Tenant Exists (Prevent FK Violations)
	// Phase 35 Hardening: Ensure the tenant ID is valid before lookup
	_, err := s.queries.GetTenantByID(ctx, pgtype.UUID{Bytes: input.TenantID, Valid: true})
	if err != nil {
		// Log internal warning for debugging
		// But return generic error or ErrTenantRequired to client
		return nil, ErrTenantRequired
	}

	user, err := s.queries.GetUserByEmail(ctx, db.GetUserByEmailParams{
		Email:    input.Email,
		TenantID: pgtype.UUID{Bytes: input.TenantID, Valid: true},
	})
	if err != nil {
		// Use a generic error to prevent user enumeration
		return nil, ErrInvalidCredentials
	}

	// 2. Verify Password
	if !user.PasswordHash.Valid {
		return nil, ErrInvalidCredentials // User has no password (maybe social login only)
	}

	if err := s.passwordHasher.Compare(user.PasswordHash.String, input.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	// 2.5 Check MFA
	if user.MfaEnabled {
		// Generate Pre-Auth Token (Phase 35 Hardening)
		preAuthToken, err := s.tokenProvider.GeneratePreAuthToken(uuid.UUID(user.ID.Bytes))
		if err != nil {
			return nil, fmt.Errorf("failed to generate pre-auth token: %w", err)
		}

		return &LoginResult{
			MfaRequired:  true,
			PreAuthToken: preAuthToken,
			User:         user,
		}, nil
	}

	// 3. Generate Access Token
	// Resolve tenant and role using helper (reduces duplication)
	tenantID, role, err := s.resolveTenantAndRole(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve tenant context: %w", err)
	}

	accessToken, err := s.tokenProvider.GenerateAccessToken(uuid.UUID(user.ID.Bytes), tenantID, role)
	if err != nil {
		return nil, fmt.Errorf("token generation failed: %w", err)
	}

	// 4. Generate Refresh Token
	refreshToken, err := GenerateSecureToken(64)
	if err != nil {
		return nil, err
	}
	refreshTokenHash := hashToken(refreshToken)

	// 5. Store Refresh Token
	// Note: Login creates a new Family.
	// Expires: 7 Days (Configurable?)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	_, err = s.queries.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:        pgtype.UUID{Bytes: user.ID.Bytes, Valid: true},
		TokenHash:     refreshTokenHash,
		ParentTokenID: pgtype.UUID{Valid: false},                   // Root of family
		FamilyID:      pgtype.UUID{Bytes: uuid.New(), Valid: true}, // New Family
		TenantID:      pgtype.UUID{Bytes: tenantID, Valid: true},
		IpAddress:     input.IP,
		UserAgent:     pgtype.Text{String: input.UserAgent, Valid: true},
		ExpiresAt:     pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// AUDIT LOG: SUCCESS
	s.audit.Log(ctx, "auth.login.success", audit.LogParams{
		ActorID:  user.ID.Bytes,
		TargetID: user.ID.Bytes,
		TenantID: tenantID, // Might be Nil if no default tenant
		Metadata: map[string]interface{}{
			"method": "password",
			"ip":     input.IP.String(),
		},
	})

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken, // Return RAW token
		User:         user,
		MfaRequired:  false,
	}, nil
}

// VerifyLoginBackupCode allows login via recovery code.
func (s *AuthService) VerifyLoginBackupCode(ctx context.Context, preAuthToken string, code string, tenantID uuid.UUID, ip net.IP, userAgent string) (*LoginResult, error) {
	// 1. Validate Pre-Auth Token (Phase 35 Hardening)
	claims, err := s.tokenProvider.ValidateToken(preAuthToken)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if claims.Scope != "pre_auth" {
		return nil, errors.New("invalid token scope")
	}
	userID := claims.UserID

	hashed := hashToken(code)

	// Check DB
	backupCode, err := s.queries.GetBackupCode(ctx, db.GetBackupCodeParams{
		UserID:   pgtype.UUID{Bytes: userID, Valid: true},
		CodeHash: hashed,
	})
	if err != nil {
		return nil, errors.New("invalid backup code")
	}

	// Consume it
	if err := s.queries.ConsumeBackupCode(ctx, backupCode.ID); err != nil {
		return nil, err
	}

	// Issue Tokens (Success)
	user, _ := s.queries.GetUserByID(ctx, db.GetUserByIDParams{
		ID:       pgtype.UUID{Bytes: userID, Valid: true},
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
	})

	tenantID, role, err := s.resolveTenantAndRole(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve tenant context: %w", err)
	}

	accessToken, err := s.tokenProvider.GenerateAccessToken(uuid.UUID(user.ID.Bytes), tenantID, role)
	if err != nil {
		return nil, err
	}

	// 4. Generate Refresh Token
	refreshToken, err := GenerateSecureToken(64)
	if err != nil {
		return nil, err
	}
	refreshTokenHash := hashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	_, err = s.queries.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:        pgtype.UUID{Bytes: user.ID.Bytes, Valid: true},
		TokenHash:     refreshTokenHash,
		ParentTokenID: pgtype.UUID{Valid: false},
		FamilyID:      pgtype.UUID{Bytes: uuid.New(), Valid: true},
		TenantID:      pgtype.UUID{Bytes: tenantID, Valid: true},
		IpAddress:     ip,
		UserAgent:     pgtype.Text{String: userAgent, Valid: true},
		ExpiresAt:     pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// AUDIT LOG
	s.audit.Log(ctx, "auth.login.success", audit.LogParams{
		ActorID:  user.ID.Bytes,
		TargetID: user.ID.Bytes,
		TenantID: tenantID,
		Metadata: map[string]interface{}{
			"method": "mfa_backup_code",
		},
	})

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
		MfaRequired:  false,
	}, nil
}

// VerifyLoginMFA completes the login for MFA-enabled users.
// NOW REQUIRES Pre-Auth Token (Phase 35 Hardening).
func (s *AuthService) VerifyLoginMFA(ctx context.Context, preAuthToken string, code string, tenantID uuid.UUID, ip net.IP, userAgent string) (*LoginResult, error) {
	// 1. Validate Pre-Auth Token
	claims, err := s.tokenProvider.ValidateToken(preAuthToken)
	if err != nil {
		return nil, ErrInvalidCredentials // Token invalid/expired
	}
	if claims.Scope != "pre_auth" {
		return nil, errors.New("invalid token scope for mfa verification")
	}
	userID := claims.UserID

	// 2. Lookup User
	user, err := s.queries.GetUserByID(ctx, db.GetUserByIDParams{
		ID:       pgtype.UUID{Bytes: userID, Valid: true},
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
	})
	if err != nil {
		return nil, ErrUserNotFound
	}

	if !user.MfaEnabled || !user.MfaSecret.Valid {
		return nil, errors.New("mfa not enabled")
	}

	if !s.mfaService.ValidateCode(code, user.MfaSecret.String) {
		return nil, ErrInvalidCode
	}

	// 3. Generate Access Token (and Refresh Token)
	tenantID, role, err := s.resolveTenantAndRole(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve tenant context: %w", err)
	}

	accessToken, err := s.tokenProvider.GenerateAccessToken(uuid.UUID(user.ID.Bytes), tenantID, role)
	if err != nil {
		return nil, fmt.Errorf("token generation failed: %w", err)
	}

	// 4. Generate Refresh Token
	refreshToken, err := GenerateSecureToken(64)
	if err != nil {
		return nil, err
	}
	refreshTokenHash := hashToken(refreshToken)

	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	_, err = s.queries.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:        pgtype.UUID{Bytes: user.ID.Bytes, Valid: true},
		TokenHash:     refreshTokenHash,
		ParentTokenID: pgtype.UUID{Valid: false},
		FamilyID:      pgtype.UUID{Bytes: uuid.New(), Valid: true},
		TenantID:      pgtype.UUID{Bytes: tenantID, Valid: true},
		IpAddress:     ip,
		UserAgent:     pgtype.Text{String: userAgent, Valid: true},
		ExpiresAt:     pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// AUDIT LOG
	s.audit.Log(ctx, "auth.login.success", audit.LogParams{
		ActorID:  user.ID.Bytes,
		TargetID: user.ID.Bytes,
		TenantID: tenantID,
		Metadata: map[string]interface{}{
			"method": "mfa_totp",
		},
	})

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
		MfaRequired:  false,
	}, nil
}
