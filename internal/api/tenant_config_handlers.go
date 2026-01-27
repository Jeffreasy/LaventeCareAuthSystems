package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/jackc/pgx/v5/pgtype"
)

// UpdateCORSOriginsRequest defines the request body for updating CORS origins
type UpdateCORSOriginsRequest struct {
	AllowedOrigins []string `json:"allowed_origins"`
}

// UpdateCORSOrigins allows admins to update allowed CORS origins
// Requires admin role
//
// ✅ SECURE: Validates CORS origins to reject wildcard (*) and enforce HTTPS
func (h *AuthHandler) UpdateCORSOrigins(w http.ResponseWriter, r *http.Request) {
	// 1. Get current tenant from context
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		http.Error(w, "Tenant context required", http.StatusBadRequest)
		return
	}

	// 2. Decode request
	var req UpdateCORSOriginsRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("UpdateCORSOrigins: Invalid request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 3. ✅ SECURITY: Validate CORS origins
	if err := storage.ValidateCORSOrigins(req.AllowedOrigins); err != nil {
		slog.Warn("UpdateCORSOrigins: Invalid CORS origins",
			"tenant_id", tenantID,
			"origins", req.AllowedOrigins,
			"error", err,
		)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 4. Get current tenant config to preserve other fields
	queries := db.New(h.Pool)
	currentTenant, err := queries.GetTenantByID(r.Context(), pgtype.UUID{Bytes: tenantID, Valid: true})
	if err != nil {
		slog.Error("UpdateCORSOrigins: Failed to get tenant",
			"tenant_id", tenantID,
			"error", err,
		)
		http.Error(w, "Failed to update CORS origins", http.StatusInternalServerError)
		return
	}

	// 5. Update only allowed_origins, preserve other fields
	params := db.UpdateTenantConfigParams{
		ID:             pgtype.UUID{Bytes: tenantID, Valid: true},
		AllowedOrigins: req.AllowedOrigins,
		RedirectUrls:   currentTenant.RedirectUrls,
		Branding:       currentTenant.Branding,
		Settings:       currentTenant.Settings,
		AppUrl:         currentTenant.AppUrl,
	}

	updatedTenant, err := queries.UpdateTenantConfig(r.Context(), params)
	if err != nil {
		slog.Error("UpdateCORSOrigins: Database update failed",
			"tenant_id", tenantID,
			"error", err,
		)
		http.Error(w, "Failed to update CORS origins", http.StatusInternalServerError)
		return
	}

	// 6. Return updated origins
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tenant_id":       tenantID,
		"allowed_origins": updatedTenant.AllowedOrigins,
		"updated_at":      updatedTenant.UpdatedAt.Time,
	})
}

// GetTenantConfig retrieves tenant configuration
// Requires admin role
func (h *AuthHandler) GetTenantConfig(w http.ResponseWriter, r *http.Request) {
	// 1. Get current tenant from context
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		http.Error(w, "Tenant context required", http.StatusBadRequest)
		return
	}

	// 2. Fetch configuration using Pool
	queries := db.New(h.Pool)
	config, err := queries.GetTenantConfig(r.Context(), pgtype.UUID{Bytes: tenantID, Valid: true})
	if err != nil {
		slog.Error("GetTenantConfig: Database query failed",
			"tenant_id", tenantID,
			"error", err,
		)
		http.Error(w, "Failed to retrieve configuration", http.StatusInternalServerError)
		return
	}

	// 3. Return configuration
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"allowed_origins": config.AllowedOrigins,
		"app_url":         config.AppUrl,
	})
}
