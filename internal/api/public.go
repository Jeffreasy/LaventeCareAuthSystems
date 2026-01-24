package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/go-chi/chi/v5"
)

// PublicHandler serves endpoints that require no authentication.
type PublicHandler struct {
	queries *db.Queries
}

func NewPublicHandler(queries *db.Queries) *PublicHandler {
	return &PublicHandler{queries: queries}
}

// GetTenantInfo allows a frontend to discover tenant details by slug (Public).
func (h *PublicHandler) GetTenantInfo(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")

	if slug == "" {
		http.Error(w, "Slug required", http.StatusBadRequest)
		return
	}

	// Anti-Gravity: Rate Limit protects this (applied globally in router).
	tenant, err := h.queries.GetTenantBySlug(r.Context(), slug)
	if err != nil {
		// Log debug, but return standard 404
		slog.Debug("Tenant discovery failed", "slug", slug, "error", err)
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	// Return Safe Data
	resp := map[string]string{
		"id":      tenant.ID.String(), // UUID to string
		"name":    tenant.Name,
		"slug":    tenant.Slug,
		"app_url": tenant.AppUrl,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
