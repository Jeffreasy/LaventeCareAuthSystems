package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/getsentry/sentry-go"
)

// PanicRecovery middleware captures panics, logs them securely, and ensures a generic 500 response.
func PanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// 1. Log to Slog (Server-side) with Stack Trace
				stack := string(debug.Stack())
				slog.Error("PANIC RECOVERED",
					"error", err,
					"path", r.URL.Path,
					"method", r.Method,
					"ip", r.RemoteAddr,
					"stack", stack,
				)

				// 2. Report to Sentry (if active)
				if hub := sentry.GetHubFromContext(r.Context()); hub != nil {
					hub.Recover(err)
				}

				// 3. Respond with Generic Error (Client-side)
				// Prevent double-write if response already started?
				// http.Error handles this mostly, but good to be safe.
				// We assume if panic happened, we probably haven't written much valid data yet
				// or we don't care about truncation.
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
