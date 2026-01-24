package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
)

// AuthMiddleware creates a handler that validates JWT tokens.
func AuthMiddleware(provider auth.TokenProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
				return
			}

			tokenStr := parts[1]
			claims, err := provider.ValidateToken(tokenStr)
			if err != nil {
				slog.Warn("Invalid Token", "error", err, "ip", r.RemoteAddr)
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Tenant Context Check
			// If X-Tenant-ID header was provided (handled by previous TenantContext middleware),
			// we MUST ensure the token grants access to THAT tenant.
			// "Anti-Gravity Law: Strict Scoping"
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
