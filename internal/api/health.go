package api

import (
	"encoding/json"
	"net/http"
)

// HealthHandler returns the enhanced health check handler
// This validates both API liveness AND database connectivity
func (s *Server) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Basic liveness check
		if s.Pool == nil {
			// Fallback if pool not set (backwards compatibility)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}

		// Advanced check: Verify database connectivity
		// Anti-Gravity Law: "The Database is a Fortress"
		ctx := r.Context()
		if err := s.Pool.Ping(ctx); err != nil {
			// Anti-Gravity Law: "Silence is Golden"
			// Log the full error internally (sent to Sentry via middleware)
			s.Logger.Error("health_check_failed", "error", err, "detail", "database_unreachable")

			// Return generic error to client (no internal state leak)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "unhealthy",
				"error":  "service temporarily unavailable",
			})
			return
		}

		// All checks passed
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "healthy",
		})
	}
}
