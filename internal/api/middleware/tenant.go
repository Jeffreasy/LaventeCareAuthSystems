package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

// TenantContext middleware checks for X-Tenant-ID header.
// It is OPTIONAL by default (as per docs), but if present, it MUST be valid.
func TenantContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantIDStr := r.Header.Get("X-Tenant-ID")

		if tenantIDStr != "" {
			// Anti-Gravity Law 1: Input is toxic. Validate strictly.
			tenantUUID, err := uuid.Parse(tenantIDStr)
			if err != nil {
				slog.Warn("Invalid Tenant ID Header", "value", tenantIDStr, "ip", r.RemoteAddr)
				http.Error(w, "Invalid Tenant ID", http.StatusBadRequest)
				return
			}

			// Law 2: Silence is Golden. We don't check if it exists in DB here (perf),
			// but we ensure syntax is correct.

			// Inject into Context
			ctx := context.WithValue(r.Context(), TenantIDKey, tenantUUID)

			// Inject into Sentry (using our helper)
			SetSentryTenant(ctx, tenantUUID.String(), "header-provided")

			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// No header? Continue without context.
		next.ServeHTTP(w, r)
	})
}
