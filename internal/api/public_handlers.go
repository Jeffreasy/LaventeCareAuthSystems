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

type ShowcaseTenant struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	AppURL      string `json:"app_url"`
	LogoURL     string `json:"logo_url"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

// GetShowcase returns a public list of featured tenants.
func (h *PublicHandler) GetShowcase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Anti-Gravity: Check DB
	tenants, err := h.queries.ListShowcaseTenants(ctx)
	if err != nil {
		slog.Error("failed to list showcase tenants", "error", err)
		http.Error(w, "Service Unavailable", http.StatusInternalServerError)
		return
	}

	response := make([]ShowcaseTenant, len(tenants))
	for i, t := range tenants {
		// Handle NULLABLE fields safely
		logo := ""
		if t.LogoUrl.Valid {
			logo = t.LogoUrl.String
		}

		desc := ""
		if t.Description.Valid {
			desc = t.Description.String
		}

		cat := "General"
		if t.Category.Valid {
			cat = t.Category.String
		}

		response[i] = ShowcaseTenant{
			Name:        t.Name,
			Slug:        string(t.Slug),
			AppURL:      t.AppUrl,
			LogoURL:     logo,
			Description: desc,
			Category:    cat,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
