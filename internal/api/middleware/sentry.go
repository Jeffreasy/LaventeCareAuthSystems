package middleware

import (
	"context"
)

// SetSentryTenant adds tenant context to the Sentry scope.
func SetSentryTenant(ctx context.Context, tenantID string, source string) {
	// Stub implementation to satisfy compiler.
	// In production, this would be:
	// sentry.ConfigureScope(func(scope *sentry.Scope) {
	// 	scope.SetTag("tenant_id", tenantID)
	// 	scope.SetTag("tenant_source", source)
	// })
}

// SetSentryUser adds user context to the Sentry scope.
func SetSentryUser(ctx context.Context, userID string, email string, ip string) {
	// Stub implementation.
	// sentry.ConfigureScope(func(scope *sentry.Scope) {
	// 	scope.SetUser(sentry.User{ID: userID, Email: email, IPAddress: ip})
	// })
}
