package api

import (
	"errors"
	"log/slog"
	"net/http"
	"unicode/utf8"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
)

type UpdateProfileRequest struct {
	FullName string `json:"full_name"`
}

// UpdateProfile allows a user to change their display name.
func (h *AuthHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	// 1. Context
	userID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Input
	var req UpdateProfileRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.FullName) > 100 {
		http.Error(w, "Name too long", http.StatusBadRequest)
		return
	}

	// 3. Action
	if err := h.service.UpdateProfile(r.Context(), userID, req.FullName); err != nil {
		slog.Error("UpdateProfile failed", "user", userID, "error", err)
		http.Error(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"updated"}`))
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ChangePassword allows a user to rotate their credentials.
// SECURITY: Revokes all active sessions upon success ("Nuclear Option").
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	// 1. Context
	userID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Input
	var req ChangePasswordRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		http.Error(w, "Both old and new passwords are required", http.StatusBadRequest)
		return
	}

	if utf8.RuneCountInString(req.NewPassword) < 12 {
		http.Error(w, "New password must be at least 12 characters", http.StatusBadRequest)
		return
	}

	// 3. Action
	err = h.service.ChangePassword(r.Context(), userID, req.OldPassword, req.NewPassword)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			slog.Warn("ChangePassword: Old password incorrect", "user", userID)
			http.Error(w, "Current password incorrect", http.StatusUnauthorized)
			return
		}
		slog.Error("ChangePassword failed", "user", userID, "error", err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	// 4. Success -> Clear current session cookies (Force re-login)
	// Even though we revoked sessions in DB, the browser might validly send the same cookie again.
	// But the DB check will fail.
	// UX Decision: Do we leave them logged in?
	// If we revoked ALL sessions, the current refresh token is also gone.
	// So next Refresh() calls will fail.
	// BUT the Access Token (15min) is JWT statelss (usually)?
	// If we use database-backed tokens (which we do for Refresh), they are gone.
	// If Access Token is JWT, it remains valid until expiry unless we blacklist JTI.
	// For now, let's clear cookies to force immediate visual logout or re-login flow.
	h.clearCookies(w)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"password_changed", "message":"All sessions revoked. Please log in again."}`))
}
