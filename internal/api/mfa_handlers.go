package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
	"github.com/google/uuid"
)

// MFA Verification Request
type VerifyMFARequest struct {
	UserID uuid.UUID `json:"user_id"` // Returned from Login step 1
	Code   string    `json:"code"`
}

func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	var req VerifyMFARequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("MFA Verify: Invalid JSON", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Extract Pre-Auth Token from Header
	tokenString, err := helpers.ExtractBearerToken(r)
	if err != nil {
		http.Error(w, "Missing pre-auth token", http.StatusUnauthorized)
		return
	}

	ip := helpers.GetRealIP(r)
	ua := r.UserAgent()
	result, err := h.service.VerifyLoginMFA(r.Context(), tokenString, req.Code, ip, ua)
	if err != nil {
		slog.Warn("MFA Verify Failed", "user", req.UserID, "error", err)
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(result)
}

// Backup Code Verification Request
func (h *AuthHandler) VerifyBackupCode(w http.ResponseWriter, r *http.Request) {
	var req VerifyMFARequest // Re-use struct, code is the backup code
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("Backup Code Verify: Invalid JSON", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Extract Pre-Auth Token from Header
	tokenString, err := helpers.ExtractBearerToken(r)
	if err != nil {
		http.Error(w, "Missing pre-auth token", http.StatusUnauthorized)
		return
	}

	ip := helpers.GetRealIP(r)
	ua := r.UserAgent()
	result, err := h.service.VerifyLoginBackupCode(r.Context(), tokenString, req.Code, ip, ua)
	if err != nil {
		slog.Warn("Backup Code Verify Failed", "user", req.UserID, "error", err)
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(result)
}

// MFA Setup (Protected)
func (h *AuthHandler) SetupMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	resp, err := h.service.SetupMFA(r.Context(), userID)
	if err != nil {
		http.Error(w, "Failed to setup MFA", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

// MFA Activate (Protected)
type ActivateMFARequest struct {
	Secret      string   `json:"secret"`
	Code        string   `json:"code"`
	BackupCodes []string `json:"backup_codes"`
}

func (h *AuthHandler) ActivateMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var req ActivateMFARequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("Activate MFA: Invalid JSON", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.service.ActivateMFA(r.Context(), userID, req.Secret, req.Code, req.BackupCodes); err != nil {
		slog.Warn("ActivateMFA failed", "user", userID, "error", err)
		http.Error(w, "Activation failed", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"mfa_enabled"}`))
}
