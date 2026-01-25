package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
)

// Admin Invite User (Protected + RBAC)
type InviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (h *AuthHandler) InviteUser(w http.ResponseWriter, r *http.Request) {
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		http.Error(w, "Tenant context required", http.StatusBadRequest)
		return
	}

	var req InviteRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("InviteUser: Invalid JSON", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := h.service.CreateInvitation(r.Context(), req.Email, tenantID, req.Role)
	if err != nil {
		slog.Error("Invite failed", "error", err)
		http.Error(w, "Failed to create invitation", http.StatusInternalServerError)
		return
	}

	// Return token in response for MVP (normally sent via email)
	json.NewEncoder(w).Encode(map[string]string{"token": token, "link": "/register?invite=" + token})
}
