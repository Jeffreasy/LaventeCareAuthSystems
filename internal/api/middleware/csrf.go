package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// CSRFMiddleware implements the Double-Submit Cookie Pattern.
// It sets a random "csrf_token" cookie.
// State changing requests (POST, PUT, DELETE) must provide "X-CSRF-Token" header matching the cookie.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check for existing cookie
		cookie, err := r.Cookie("csrf_token")
		var token string

		if err != nil || cookie.Value == "" {
			// Generate new token
			token, err = generateRandomString(32)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Set Cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    token,
				Path:     "/",
				HttpOnly: false, // Must be readable by JS to be sent in Header!
				Secure:   true,  // Production only check recommended
				SameSite: http.SameSiteStrictMode,
			})
		} else {
			token = cookie.Value
		}

		// 2. Validate Header for Unsafe Methods
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" || r.Method == "PATCH" {
			headerToken := r.Header.Get("X-CSRF-Token")
			if headerToken == "" || !SecureCompareCSRFTokens(headerToken, token) {
				http.Error(w, "CSRF Token Mismatch", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SecureCompareCSRFTokens performs a constant-time comparison of CSRF tokens.
// This prevents timing attacks where an attacker could measure response times
// to guess valid CSRF tokens.
//
// ✅ SECURE: Uses crypto/subtle.ConstantTimeCompare
func SecureCompareCSRFTokens(provided, expected string) bool {
	providedBytes := []byte(provided)
	expectedBytes := []byte(expected)
	return subtle.ConstantTimeCompare(providedBytes, expectedBytes) == 1
}
