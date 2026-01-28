package middleware

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"slices"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/google/uuid"
)

type CorsConfigProvider interface {
	GetTenantConfig(ctx context.Context, id uuid.UUID) (db.GetTenantConfigRow, error)
}

// DynamicCorsMiddleware enforces Tenant-specific CORS policies.
// It assumes TenantContext middleware has already run and populated a possible TenantID.
// For Preflight (OPTIONS), it reflects the Origin to allow the browser to send the actual request.
func DynamicCorsMiddleware(q CorsConfigProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Not a CORS request, proceed.
				next.ServeHTTP(w, r)
				return
			}

			// Preflight Handling independent of Tenant
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Origin", origin) // Reflect
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Requested-With")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.WriteHeader(http.StatusOK)
				return
			}

			// Actual Request: Validate Origin against Tenant Config
			tenantID, err := GetTenantID(r.Context())
			if err != nil {
				// No Tenant ID? If it's a public endpoint, maybe allow?
				// For "Anti-Gravity", if no tenant, maybe default strict?
				// User requirements imply this is for "Astro App" clients vs existing API.
				// We'll fallback to strict (reject) or Reflect if it's the Main Portal?
				// Let's Log and Reject for now to be safe, or allow if it matches System Origin (todo).
				// Logic: If no tenant header, we can't validate against tenant config.
				// Check if the route allows anonymous?
				// We'll proceed but NOT set CORS headers, effectively blocking browser clients.
				next.ServeHTTP(w, r)
				return
			}

			// Fetch Config
			// Use r.Context() which might have timeout attached upstream?
			// Use a detached context for DB check to avoid canceling on client disconnect during check? No, standard ctx is fine.
			config, err := q.GetTenantConfig(r.Context(), tenantID)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					// Invalid Tenant ID was passed (though TenantContext validated UUID syntax)
					slog.Warn("CORS: Tenant not found in DB", "tenant_id", tenantID)
					http.Error(w, "Invalid Tenant", http.StatusForbidden)
					return
				}
				slog.Error("CORS: DB Error", "err", err)
				http.Error(w, "Internal Error", http.StatusInternalServerError)
				return
			}

			// Check Origin
			// allowed_origins is TEXT[] -> []string
			// SYSTEM OVERRIDE: Allow Localhost for Development
			isLocalDev := origin == "http://localhost:4321" || origin == "http://localhost:3000"

			if isLocalDev || slices.Contains(config.AllowedOrigins, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			} else {
				// Anti-Gravity Law 1: Toxic Input.
				// We do NOT set headers. Browser will block response reading.
				// Optional: Log violation
				slog.Warn("CORS: Origin Rejected", "tenant_id", tenantID, "origin", origin)
				// We do NOT stop execution here?
				// Actually CORS spec says server *can* process process, but browser won't show result.
				// But to save resources, we could abort.
				// "Blokkeer (of negeer)" -> Let's Block with 403 to be "Anti-Gravity".
				http.Error(w, "CORS Policy Violation", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
