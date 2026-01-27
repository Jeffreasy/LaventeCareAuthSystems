package storage

import (
	"errors"
	"strings"
)

// ValidateCORSOrigins validates that CORS origins are secure.
// Rejects wildcard (*) origins and enforces HTTPS-only (except localhost).
//
// ✅ SECURE: Prevents wildcard CORS misconfiguration
// ✅ SECURE: Enforces TLS for production origins
//
// This should be called when updating tenant configuration via admin endpoints.
func ValidateCORSOrigins(origins []string) error {
	for _, origin := range origins {
		// ❌ REJECT: Wildcard CORS allows any origin
		if origin == "*" {
			return errors.New("wildcard CORS origin not allowed")
		}

		// ❌ REJECT: HTTP (except localhost for development)
		if !strings.HasPrefix(origin, "https://") && !strings.HasPrefix(origin, "http://localhost") {
			return errors.New("only HTTPS origins allowed (except http://localhost for development)")
		}

		// Additional validation: Ensure valid URL format
		if origin == "" || strings.Contains(origin, " ") {
			return errors.New("invalid origin format")
		}
	}

	return nil
}
