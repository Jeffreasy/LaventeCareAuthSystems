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

// Logout revokes the refresh token family, effectively killing the session on all devices sharing that family.
// In a stricter mode, we might blacklist the Access Token ID (jti) in Redis until expiry.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	hashed := hashToken(refreshToken)

	// Enhancement: Fetch token to identify user for Audit Logging
	// We perform a lookup before revocation to capture WHO is logging out.
	token, err := s.queries.GetRefreshToken(ctx, hashed)
	if err == nil {
		// Found token, log the event
		s.audit.Log(ctx, "auth.logout", audit.LogParams{
			ActorID:  token.UserID.Bytes,
			TargetID: token.UserID.Bytes,
			TenantID: token.TenantID.Bytes,
			Metadata: map[string]interface{}{
				"method":    "token_revocation",
				"family_id": token.FamilyID.Bytes,
			},
		})
	}

	// Always attempt revocation (Idempotent / Silence is Golden)
	return s.queries.RevokeTokenFamily(ctx, hashed)
}

// RefreshSession performs secure token rotation.
// It detects reuse (revoked tokens) and invalidates family if found.
func (s *AuthService) RefreshSession(ctx context.Context, refreshToken string, ip net.IP, userAgent string) (*LoginResult, error) {
	hashed := hashToken(refreshToken)

	// 1. Fetch Token (Silence is Golden, but we need to know status)
	token, err := s.queries.GetRefreshToken(ctx, hashed)
	if err != nil {
		return nil, ErrInvalidCredentials // Not found
	}

	// 2. Reuse Detection (Anti-Gravity)
	// 2. Reuse Detection (Anti-Gravity)
	if token.IsRevoked {
		// Phase 35: Grace Period Check
		// If reused within 10 seconds of revocation, we assume concurrent requests (UI race condition).
		// We return error but DO NOT trigger the Nuclear Option (Family Revocation).
		const gracePeriod = 10 * time.Second
		if token.RevokedAt.Valid && time.Since(token.RevokedAt.Time) < gracePeriod {
			// Log but don't nuke
			// slog is not imported in service.go usually, we return error.
			// Ideally we log this.
			// return nil, ErrConcurrentRefresh (we use generic string for now or specific error?)
			// User request: "Concurrent Refresh"
			return nil, errors.New("concurrent refresh request")
		}

		// ALARM: Token Reuse Detected!
		// Nuclear Option: Revoke entire family
		// Log this critical security event
		s.queries.RevokeTokenFamily(ctx, hashed)
		return nil, errors.New("security alert: token reuse detected")
	}

	// 3. Expiry Check
	// 3. Expiry Check
	if time.Now().After(token.ExpiresAt.Time) {
		return nil, errors.New("session expired")
	}

	// 4. Rotate (Generate New Token)
	newRawToken, err := GenerateSecureToken(64)
	if err != nil {
		return nil, err
	}
	newHashed := hashToken(newRawToken)

	// 5. Atomic DB Update (Rotate)
	_, err = s.queries.RotateRefreshToken(ctx, db.RotateRefreshTokenParams{
		OldTokenHash: hashed,
		NewTokenHash: newHashed,
		ExpiresAt:    pgtype.Timestamptz{Time: time.Now().Add(7 * 24 * time.Hour), Valid: true}, // 7 Days
		IpAddress:    ip,
		UserAgent:    pgtype.Text{String: userAgent, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("rotation failed: %w", err)
	}

	// 6. Generate New Access Token
	// Need to fetch user to get latest role/tenant? Or use token data?
	// Using stored UserID. TenantID is in RefreshToken (inherited).
	// 6. Generate New Access Token
	// Using stored UserID. TenantID is in RefreshToken (inherited).
	user, err := s.queries.GetUserByID(ctx, db.GetUserByIDParams{
		ID:       token.UserID,
		TenantID: token.TenantID,
	})
	if err != nil {
		return nil, ErrUserNotFound
	}

	tenantID, role, err := s.resolveTenantAndRole(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve tenant context: %w", err)
	}

	accessToken, err := s.tokenProvider.GenerateAccessToken(uuid.UUID(user.ID.Bytes), tenantID, role)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: newRawToken,
		User:         user,
	}, nil
}

func (s *AuthService) GetSessions(ctx context.Context, userID uuid.UUID) ([]db.RefreshToken, error) {
	return s.queries.GetSessionsByUser(ctx, pgtype.UUID{Bytes: userID, Valid: true})
}

func (s *AuthService) RevokeSession(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error {
	return s.queries.RevokeSession(ctx, db.RevokeSessionParams{
		ID:     pgtype.UUID{Bytes: sessionID, Valid: true},
		UserID: pgtype.UUID{Bytes: userID, Valid: true},
	})
}
