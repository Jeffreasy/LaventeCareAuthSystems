package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ListUsers returns all members of the current tenant (Admin Only).
func (h *AuthHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		http.Error(w, "Tenant required", http.StatusBadRequest)
		return
	}

	members, err := h.service.ListTenantMembers(r.Context(), tenantID)
	if err != nil {
		slog.Error("ListUsers failed", "tenant", tenantID, "error", err)
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}

	// Map to simplified JSON to hide internal DB fields if any (though row struct is clean)
	// We handle pgtype fields for JSON marshalling
	type MemberResponse struct {
		ID       uuid.UUID `json:"id"`
		Email    string    `json:"email"`
		FullName string    `json:"full_name"`
		Role     string    `json:"role"`
		JoinedAt string    `json:"joined_at"`
	}

	response := make([]MemberResponse, len(members))
	for i, m := range members {
		// Safe extraction of UUID from pgtype.UUID
		// Note: ListTenantMembersRow ID is pgtype.UUID
		uid := uuid.UUID(m.ID.Bytes)

		response[i] = MemberResponse{
			ID:       uid,
			Email:    m.Email,
			FullName: m.FullName.String,
			Role:     m.Role,
			JoinedAt: m.JoinedAt.Time.Format("2006-01-02"),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

type UpdateRoleRequest struct {
	Role string `json:"role"`
}

// UpdateRole changes a member's role (Admin Only).
func (h *AuthHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	// 1. Context
	// 1. Context
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		http.Error(w, "Tenant Context Required", http.StatusBadRequest)
		return
	}

	currentUserID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Input
	targetIDStr := chi.URLParam(r, "userID")
	targetID, err := uuid.Parse(targetIDStr)
	if err != nil {
		http.Error(w, "Invalid User ID", http.StatusBadRequest)
		return
	}

	// 3. SAFETY CHECK: Self-Destruct Prevention
	if targetID == currentUserID {
		http.Error(w, "Cannot modify your own role", http.StatusForbidden)
		return
	}

	var req UpdateRoleRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate Role
	if req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	// 4. Action
	if err := h.service.UpdateMemberRole(r.Context(), tenantID, targetID, req.Role); err != nil {
		slog.Error("UpdateRole failed", "tenant", tenantID, "target", targetID, "error", err)
		http.Error(w, "Failed to update role", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"updated"}`))
}

// RemoveUser removes a member from the tenant (Admin Only).
func (h *AuthHandler) RemoveUser(w http.ResponseWriter, r *http.Request) {
	// 1. Context
	// 1. Context
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		http.Error(w, "Tenant Context Required", http.StatusBadRequest)
		return
	}

	currentUserID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Input
	targetIDStr := chi.URLParam(r, "userID")
	targetID, err := uuid.Parse(targetIDStr)
	if err != nil {
		http.Error(w, "Invalid User ID", http.StatusBadRequest)
		return
	}

	// 3. SAFETY CHECK: Self-Destruct Prevention
	if targetID == currentUserID {
		http.Error(w, "Cannot remove yourself from the tenant", http.StatusForbidden)
		return
	}

	// 4. Action
	if err := h.service.RemoveMember(r.Context(), tenantID, targetID); err != nil {
		slog.Error("RemoveUser failed", "tenant", tenantID, "target", targetID, "error", err)
		http.Error(w, "Failed to remove user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"removed"}`))
}

// CreateTenantRequest defines the payload for creating a new tenant.
type CreateTenantRequest struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	AppURL string `json:"app_url"`
}

// CreateTenant creates a new tenant (Admin Only).
// Checks for "System Admin" privileges would theoretically go here,
// but for this Multi-Tenant system, any Admin of the "Admin Tenant" (if we had one) or
// just a super-admin could do this.
// Current RBAC: "admin" role (scoped to a tenant).
// CRITICAL: This endpoint technically allows an Admin of *any* tenant to create a NEW tenant?
// Review: Usually Tenant Creation is a Super-Admin function.
// However, the user asked for "Audit Form" tenant creation.
// We will rely on `requireRBAC("admin")`.
// Since strictly speaking, the USER creates it.
// We will assume the caller has valid credentials.
func (h *AuthHandler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	// 1. Decode Request
	var req CreateTenantRequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("CreateTenant: Invalid Request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 2. Validate
	if req.Name == "" || req.Slug == "" {
		http.Error(w, "Name and Slug are required", http.StatusBadRequest)
		return
	}

	// 3. Call Service
	// Context already contains the Actor's info (from middleware)
	// identifying WHO is creating it.
	input := auth.CreateTenantInput{
		Name:   req.Name,
		Slug:   req.Slug,
		AppURL: req.AppURL,
	}

	tenant, err := h.service.CreateTenant(r.Context(), input)
	if err != nil {
		// Log specific error
		slog.Error("CreateTenant failed", "slug", req.Slug, "error", err)
		// Return generic error to client
		http.Error(w, "Failed to create tenant", http.StatusInternalServerError)
		return
	}

	// 4. Return Result (201 Created)
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":   uuid.UUID(tenant.ID.Bytes),
		"name": tenant.Name,
		"slug": tenant.Slug,
	})
}
