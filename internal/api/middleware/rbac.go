package middleware

import (
	"log/slog"
	"net/http"
)

// Roles
const (
	RoleAdmin  = "admin"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

// RoleWeights for hierarchy checks
var roleWeights = map[string]int{
	RoleAdmin:  3,
	RoleEditor: 2,
	RoleViewer: 1,
}

// RBACMiddleware creates a middleware that enforces role access.
// It requires AuthMiddleware AND TenantContext middleware to run first.
// RBACMiddleware creates a middleware that enforces role access.
// It requires AuthMiddleware AND TenantContext middleware to run first.
// HIGH-2 Optimization: Uses Claims-based Role from context instead of DB query.
func RBACMiddleware() func(requiredRole string) func(next http.Handler) http.Handler {
	return func(requiredRole string) func(next http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 1. Get UserID (Safety Check)
				if _, err := GetUserID(r.Context()); err != nil {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				// 2. Get Role from Context (Injected by AuthMiddleware from Token Claims)
				role, err := GetRole(r.Context())
				if err != nil {
					slog.Warn("RBAC: Role missing in context", "ip", r.RemoteAddr)
					http.Error(w, "Forbidden (No Role)", http.StatusForbidden)
					return
				}

				// 3. Hierarchy Check
				userWeight := roleWeights[role]
				requiredWeight := roleWeights[requiredRole]

				if userWeight < requiredWeight {
					slog.Warn("RBAC: Insufficient Permissions", "have", role, "need", requiredRole)
					http.Error(w, "Forbidden (Insufficient Permissions)", http.StatusForbidden)
					return
				}

				next.ServeHTTP(w, r)
			})
		}
	}
}
