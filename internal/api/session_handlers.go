package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// GetSessions returns active sessions for the current user.
func (h *AuthHandler) GetSessions(w http.ResponseWriter, r *http.Request) {
	userID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sessions, err := h.service.GetSessions(r.Context(), userID)
	if err != nil {
		slog.Error("GetSessions failed", "error", err)
		http.Error(w, "Failed to fetch sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

// RevokeSession kills a specific session.
func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	sessionIDStr := chi.URLParam(r, "id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		http.Error(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	if err := h.service.RevokeSession(r.Context(), userID, sessionID); err != nil {
		slog.Error("RevokeSession failed", "error", err)
		http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
