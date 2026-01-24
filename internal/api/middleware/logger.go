package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// RequestLogger is a middleware that logs the start and end of each request.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := middleware.GetReqID(r.Context()) // Get ID from Chi

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Log Request Start? Optional. Keep it clean for now.

		next.ServeHTTP(ww, r)

		// Log Request End
		duration := time.Since(start)

		level := slog.LevelInfo
		if ww.Status() >= 500 {
			level = slog.LevelError
		} else if ww.Status() >= 400 {
			level = slog.LevelWarn
		}

		slog.Log(r.Context(), level, "http_request_completed",
			"status", ww.Status(),
			"method", r.Method,
			"path", r.URL.Path,
			"duration", duration,
			"req_id", reqID,
			"ip", r.RemoteAddr,
		)
	})
}
