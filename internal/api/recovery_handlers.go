package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
)

// RequestPasswordResetRequest defines request body for password reset initiation
type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

// RequestPasswordReset handles POST /auth/password/forgot
// Initiates password reset flow by sending email with reset token
//
// ✅ SECURE: Always returns success to prevent email enumeration
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	// 1. Get tenant from context
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		http.Error(w, "Tenant context required", http.StatusBadRequest)
		return
	}

	// 2. Decode request
	var req RequestPasswordResetRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("RequestPasswordReset: Invalid request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 3. Basic email validation
	if req.Email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// 4. Call service (ALWAYS returns nil for security - prevents email enumeration)
	// Even if email doesn't exist, we pretend to send the email
	_ = h.service.RequestPasswordReset(r.Context(), req.Email, tenantID)

	// 5. Generic success response (don't leak if email exists)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If the email exists, a reset link has been sent",
	})
}

// ResetPasswordRequest defines request body for completing password reset
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ResetPassword handles POST /auth/password/reset
// Completes password reset using token from email
//
// ✅ SECURE: Token is single-use and expires after 15 minutes
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	// 1. Decode request
	var req ResetPasswordRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("ResetPassword: Invalid request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 2. Validate inputs
	if req.Token == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 8 {
		http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	// 3. Call service to reset password
	if err := h.service.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		slog.Warn("ResetPassword: Failed", "error", err)
		http.Error(w, "Invalid or expired reset token", http.StatusUnauthorized)
		return
	}

	// 4. Success - password has been reset
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset successful. You can now log in with your new password.",
	})
}
