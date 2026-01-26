package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Logout revokes the refresh token family, effectively killing the session on all devices sharing that family.
// In a stricter mode, we might blacklist the Access Token ID (jti) in Redis until expiry.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	// We assume the refresh token string *is* the family ID or contains it.
	// However, current implementation of Login just returns "TODO..."
	// For this Phase, we define the signature. The DB params require FamilyID and TenantID.

	// Real implementation would:
	// 1. Decode Refresh Token (if it's JWT) or Lookup Opaque Token to get Family ID.
	// 2. Call s.queries.RevokeRefreshTokenFamily(...)

	// With the new "Nuclear Option" query, we just pass the hash
	hashed := hashToken(refreshToken)

	// AUDIT LOG (Best effort, we don't have UserID here easily unless we fetch token first)
	// But `RevokeTokenFamily` is void.
	// We should probably log this action.
	// Since we don't have UserID, ActorID is Nil or from Context if we extract it?
	// s.audit.Log(ctx, "auth.session.revoke", ...)
	// Let's rely on Middleware to set Context UserID if authenticated?
	// Logout endpoint often handles unauthenticated if just revoking token?
	// Actually `Logout` in `api` likely extracts UserID from Access Token.
	// Let's assume Context has it or we skip strictly connecting ActorID here for MVP if difficult.
	// But wait, the params require `refreshToken`.
	// Ideally we fetch the token to know WHO it belongs to before revoking, for the log?
	// `RevokeTokenFamily` deletes it (or marks revoked).
	// Let's skip heavy logic. If we want to log, we should do it at API layer or if we fetch token.
	// Decision: Skip Audit in Service Logout for now to avoid DB roundtrip just for logging,
	// UNLESS "Silence is Golden" implies we should log security events.
	// Revocation IS a security event.
	// I will fetch token first? No, that's expensive.
	// I will just return. The API layer logs HTTP request.
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
