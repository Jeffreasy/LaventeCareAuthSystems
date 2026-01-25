package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/mail"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
)

// Request Email Change (Protected)
type RequestEmailChangeRequest struct {
	NewEmail string `json:"new_email"`
	Password string `json:"password"`
}

func (h *AuthHandler) RequestEmailChange(w http.ResponseWriter, r *http.Request) {
	userID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var req RequestEmailChangeRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("EmailChange: Invalid JSON", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.NewEmail == "" || req.Password == "" {
		http.Error(w, "Email and password required", http.StatusBadRequest)
		return
	}

	if _, err := mail.ParseAddress(req.NewEmail); err != nil {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	token, err := h.service.RequestEmailChange(r.Context(), userID, req.NewEmail, req.Password)
	if err != nil {
		slog.Warn("RequestEmailChange failed", "user", userID, "error", err)
		http.Error(w, "Request failed", http.StatusUnauthorized)
		return
	}

	// Return token for MVP (simulate email)
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Confirm Email Change (Public - via link token, or Protected?)
// Usually public link from email.
type ConfirmEmailChangeRequest struct {
	Token string `json:"token"`
}

func (h *AuthHandler) ConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	var req ConfirmEmailChangeRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("ConfirmEmail: Invalid JSON", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.service.ConfirmEmailChange(r.Context(), req.Token); err != nil {
		slog.Warn("ConfirmEmail failed", "error", err)
		http.Error(w, "Confirmation failed", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"email_updated"}`))
}
