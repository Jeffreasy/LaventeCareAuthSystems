package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
)

// ResendVerificationRequest defines request body for resending verification email
type ResendVerificationRequest struct {
	Email string `json:"email"`
}

// ResendVerification handles POST /auth/email/resend
// Resends email verification link to user
//
// ✅ SECURE: Always returns success to prevent email enumeration
func (h *AuthHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	// 1. Get tenant from context
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		http.Error(w, "Tenant context required", http.StatusBadRequest)
		return
	}

	// 2. Decode request
	var req ResendVerificationRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("ResendVerification: Invalid request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 3. Basic validation
	if req.Email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// 4. Call service (always returns nil for security)
	// If user already verified or doesn't exist, silently succeeds
	_ = h.service.RequestEmailVerification(r.Context(), req.Email, tenantID)

	// 5. Generic success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If the email exists and is unverified, a verification link has been sent",
	})
}

// VerifyEmailRequest defines request body for email verification
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// VerifyEmail handles POST /auth/email/verify
// Completes email verification using token from email
//
// ✅ SECURE: Token is single-use and expires after 24 hours
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	// 1. Decode request
	var req VerifyEmailRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("VerifyEmail: Invalid request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 2. Validate token
	if req.Token == "" {
		http.Error(w, "Token is required", http.StatusBadRequest)
		return
	}

	// 3. Call service to verify email
	if err := h.service.VerifyEmail(r.Context(), req.Token); err != nil {
		slog.Warn("VerifyEmail: Failed", "error", err)
		http.Error(w, "Invalid or expired verification token", http.StatusUnauthorized)
		return
	}

	// 4. Success - email is now verified
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Email verified successfully. You can now access all features.",
	})
}
