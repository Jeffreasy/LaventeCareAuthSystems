package helpers

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// DecodeJSON decodes JSON from request body with strict validation.
// Enforces Anti-Gravity Law 1: "Input is Toxic"
//
// This function ensures:
// - Unknown fields are rejected (prevents payload pollution)
// - Proper error wrapping for debugging
// - Consistent validation across all handlers
//
// Usage:
//
//	var req LoginRequest
//	if err := helpers.DecodeJSON(r, &req); err != nil {
//	    http.Error(w, err.Error(), http.StatusBadRequest)
//	    return
//	}
func DecodeJSON(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // Anti-Gravity Law 1: Never trust input

	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	return nil
}
