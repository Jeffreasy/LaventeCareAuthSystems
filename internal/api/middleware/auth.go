package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
)

// extractJWT extracts JWT token from request using cookie-first strategy.
// Priority 1: HttpOnly cookie (secure, XSS-immune)
// Priority 2: Authorization header (legacy support)
//
// ✅ SECURE: Cookie-based extraction protects against XSS attacks
// as HttpOnly cookies cannot be accessed by JavaScript.
func extractJWT(r *http.Request) string {
	// Priority 1: Check for access_token cookie (SECURE)
	if cookie, err := r.Cookie("access_token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// Priority 2: Fallback to Authorization header (LEGACY)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return ""
}

// AuthMiddleware creates a handler that validates JWT tokens.
// Supports both HttpOnly cookie-based auth (preferred) and Authorization header (legacy).
func AuthMiddleware(provider auth.TokenProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ✅ Extract token using cookie-first strategy
			tokenStr := extractJWT(r)
			if tokenStr == "" {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Validate token
			claims, err := provider.ValidateToken(tokenStr)
			if err != nil {
				// Anti-Gravity Debugging: Log exact validation error
				slog.Warn("AuthMiddleware: Token Validation Failed",
					"error", err,
					"token_prefix", tokenStr[:min(10, len(tokenStr))]+"...",
					"ip", r.RemoteAddr,
				)
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}
			// Log successful validation for debugging
			slog.Info("AuthMiddleware: Token Validated", "user_id", claims.UserID, "scope", claims.Scope, "tid", claims.TenantID)

			// Tenant Context Check
			// If X-Tenant-ID header was provided (handled by previous TenantContext middleware),
			// we MUST ensure the token grants access to THAT tenant.
			// "Anti-Gravity Law: Strict Scoping"
			ctxTenantID, err := GetTenantID(r.Context())
			if err == nil {
				// Header was present and valid.
				if claims.TenantID != ctxTenantID {
					slog.Warn("Tenant Mismatch", "token_tid", claims.TenantID, "header_tid", ctxTenantID)
					http.Error(w, "Token does not match requested tenant context", http.StatusForbidden)
					return
				}
			} else {
				// No header provided? We can either:
				// 1. Enforce specific tenant context from token (Inject token TID as the context TID)
				// 2. Allow "Global" tokens (unlikely in this architecture).
				// We'll adopt option 1 for safety.
				ctx := context.WithValue(r.Context(), TenantIDKey, claims.TenantID)

				// Re-inject Sentry tag since TenantContext middleware couldn't do it (was missing header)
				SetSentryTenant(ctx, claims.TenantID.String(), "token-derived")
				r = r.WithContext(ctx)
			}

			// Inject User ID
			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, RoleKey, claims.Role) // Inject Role (Layer 2 Optimization)
			SetSentryUser(ctx, claims.UserID.String(), claims.Role, r.RemoteAddr)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
