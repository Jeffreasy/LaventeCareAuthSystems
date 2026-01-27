package auth

import (
	"crypto/subtle"
)

// SecureCompareTokens performs a constant-time comparison of two token strings.
// This prevents timing attacks where an attacker could measure response times
// to guess tokens character-by-character.
//
// ✅ SECURE: Uses crypto/subtle.ConstantTimeCompare for timing-attack resistance.
//
// Returns true if the tokens match, false otherwise.
//
// Apply to:
//   - Refresh token validation
//   - Session token validation
//   - HMAC signature verification
//   - Any cryptographic comparison
func SecureCompareTokens(provided, expected string) bool {
	// Convert strings to byte slices
	providedBytes := []byte(provided)
	expectedBytes := []byte(expected)

	// subtle.ConstantTimeCompare returns 1 if equal, 0 if not
	// It always examines all bytes regardless of differences
	return subtle.ConstantTimeCompare(providedBytes, expectedBytes) == 1
}

// SecureCompareBytes performs a constant-time comparison of two byte slices.
// Use this for HMAC signatures or other binary comparisons.
//
// ✅ SECURE: Uses crypto/subtle.ConstantTimeCompare for timing-attack resistance.
func SecureCompareBytes(provided, expected []byte) bool {
	return subtle.ConstantTimeCompare(provided, expected) == 1
}
