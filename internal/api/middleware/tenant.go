package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantContext is a middleware factory that validates and injects the tenant context.
//
// PHASE 50 RLS INTEGRATION:
// This middleware now wraps the request handler in a database transaction with
// SET LOCAL app.current_tenant for Row Level Security enforcement.
//
// Usage in router.go:
//
//	r.Use(customMiddleware.TenantContext(pool))
//
// The X-Tenant-ID header is OPTIONAL by default, but if present, it MUST be valid.
// When set, all downstream database queries will respect RLS policies.
func TenantContext(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantIDStr := r.Header.Get("X-Tenant-ID")

			// No tenant context? Continue without RLS enforcement.
			// This allows public endpoints (health, login, register) to function.
			if tenantIDStr == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Anti-Gravity Law 1: Input is toxic. Validate strictly.
			tenantUUID, err := uuid.Parse(tenantIDStr)
			if err != nil {
				slog.Warn("Invalid Tenant ID Header", "value", tenantIDStr, "ip", r.RemoteAddr)
				http.Error(w, "Invalid Tenant ID", http.StatusBadRequest)
				return
			}

			// Law 2: Silence is Golden. We don't check if it exists in DB here (perf),
			// but we ensure syntax is correct.

			// Inject into Context (for application logic)
			ctx := context.WithValue(r.Context(), TenantIDKey, tenantUUID)

			// Inject into Sentry (using our helper)
			SetSentryTenant(ctx, tenantUUID.String(), "header-provided")

			// PHASE 50 RLS: Set database session variable
			// We use WithTenantContext to wrap the downstream handler execution
			// in a transaction with SET LOCAL app.current_tenant.
			//
			// IMPORTANT: This means the ENTIRE request handler runs in ONE transaction.
			// Handlers must be idempotent and handle rollbacks properly.
			err = storage.WithTenantContext(ctx, pool, tenantUUID, func(tx pgx.Tx) error {
				// Store the transaction in context for handlers to use
				// Handlers can access via: storage.GetTx(ctx)
				ctxWithTx := context.WithValue(ctx, storage.TxKey, tx)

				// Create a custom ResponseWriter to capture errors
				rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

				// Execute the downstream handler
				next.ServeHTTP(rw, r.WithContext(ctxWithTx))

				// If handler wrote an error status (4xx/5xx), rollback
				if rw.statusCode >= 400 {
					return http.ErrAbortHandler // Triggers rollback
				}

				return nil // Commit transaction
			})

			if err != nil && err != http.ErrAbortHandler {
				// Transaction failed for reasons other than intentional abort
				slog.Error("RLS transaction failed", "error", err, "tenant_id", tenantUUID)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status codes
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
