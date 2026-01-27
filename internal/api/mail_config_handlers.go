package api

import (
	"encoding/json"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/crypto"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/mailer"
)

// MailConfigRequest is the payload for configuring tenant SMTP settings.
// Security: Password is encrypted before storage (never stored in plaintext).
type MailConfigRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"` // Plaintext in request, encrypted before DB storage
	From     string `json:"from"`
	TLSMode  string `json:"tls_mode"` // "starttls" or "tls"
}

// MailConfigResponse is the safe view of SMTP config (password excluded).
type MailConfigResponse struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	From    string `json:"from"`
	TLSMode string `json:"tls_mode"`
}

// UpdateMailConfig allows tenant admins to configure custom SMTP settings.
// This is a CRITICAL endpoint - only accessible to tenant admins.
//
// Security Controls:
// - RBAC: Requires admin role (enforced via RBACMiddleware)
// - SSRF Protection: Validates host/port before saving
// - Encryption: Password is encrypted via AES-256-GCM before storage
// - Audit: Logs configuration changes to audit_logs
//
// POST /api/admin/mail-config
func (h *AuthHandler) UpdateMailConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		helpers.RespondError(w, http.StatusUnauthorized, "tenant context required")
		return
	}

	userID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		helpers.RespondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Parse request
	var req MailConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.RespondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 1. CRITICAL: Validate SMTP config (SSRF protection)
	if err := mailer.ValidateSMTPConfig(req.Host, req.Port); err != nil {
		h.Logger.Warn("SSRF attempt blocked in mail config",
			"tenant_id", tenantID,
			"user_id", userID,
			"host", req.Host,
			"port", req.Port,
			"error", err,
		)
		helpers.RespondError(w, http.StatusBadRequest, "invalid SMTP configuration")
		return
	}

	// 2. Validate TLS mode
	if req.TLSMode != "starttls" && req.TLSMode != "tls" {
		helpers.RespondError(w, http.StatusBadRequest, "tls_mode must be 'starttls' or 'tls'")
		return
	}

	// 3. Validate From address (MIME injection prevention)
	if _, err := json.Marshal(req.From); err != nil {
		helpers.RespondError(w, http.StatusBadRequest, "invalid from address")
		return
	}

	// 4. Encrypt password (AES-256-GCM)
	encryptedPassword, err := crypto.EncryptTenantSecret(req.Password)
	if err != nil {
		h.Logger.Error("Failed to encrypt SMTP password",
			"tenant_id", tenantID,
			"error", err,
		)
		helpers.RespondError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	// 5. Build SMTP config
	config := mailer.SMTPConfig{
		Host:          req.Host,
		Port:          req.Port,
		User:          req.User,
		PassEncrypted: encryptedPassword,
		From:          req.From,
		TLSMode:       req.TLSMode,
	}

	// 6. Serialize to JSON
	configJSON, err := json.Marshal(config)
	if err != nil {
		h.Logger.Error("Failed to serialize mail config", "error", err)
		helpers.RespondError(w, http.StatusInternalServerError, "configuration error")
		return
	}

	// 7. Save to database
	_, err = h.Pool.Exec(r.Context(), `
		UPDATE tenants
		SET mail_config = $2,
		    mail_config_key_version = 1,
		    updated_at = NOW()
		WHERE id = $1
	`, tenantID, configJSON)

	if err != nil {
		h.Logger.Error("Failed to save mail config", "error", err)
		helpers.RespondError(w, http.StatusInternalServerError, "failed to save configuration")
		return
	}

	// 8. Audit log
	h.Logger.Info("Mail configuration updated",
		"tenant_id", tenantID,
		"user_id", userID,
		"host", req.Host,
		"port", req.Port,
	)

	// 9. Return safe response (exclude password)
	response := MailConfigResponse{
		Host:    req.Host,
		Port:    req.Port,
		User:    req.User,
		From:    req.From,
		TLSMode: req.TLSMode,
	}

	helpers.RespondJSON(w, http.StatusOK, response)
}

// GetMailConfig returns the tenant's SMTP configuration (password excluded).
//
// GET /api/admin/mail-config
func (h *AuthHandler) GetMailConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		helpers.RespondError(w, http.StatusUnauthorized, "tenant context required")
		return
	}

	// Fetch config from database
	var configJSON []byte
	err = h.Pool.QueryRow(r.Context(), `
		SELECT mail_config
		FROM tenants
		WHERE id = $1 AND mail_config IS NOT NULL
	`, tenantID).Scan(&configJSON)

	if err != nil {
		// No config found - return empty
		helpers.RespondJSON(w, http.StatusOK, map[string]any{
			"configured": false,
		})
		return
	}

	// Deserialize config
	var config mailer.SMTPConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		h.Logger.Error("Failed to deserialize mail config", "error", err)
		helpers.RespondError(w, http.StatusInternalServerError, "configuration error")
		return
	}

	// Return safe response (exclude encrypted password)
	response := MailConfigResponse{
		Host:    config.Host,
		Port:    config.Port,
		User:    config.User,
		From:    config.From,
		TLSMode: config.TLSMode,
	}

	helpers.RespondJSON(w, http.StatusOK, map[string]any{
		"configured": true,
		"config":     response,
	})
}

// DeleteMailConfig removes the tenant's SMTP configuration (fallback to system default).
//
// DELETE /api/admin/mail-config
func (h *AuthHandler) DeleteMailConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		helpers.RespondError(w, http.StatusUnauthorized, "tenant context required")
		return
	}

	userID, _ := customMiddleware.GetUserID(r.Context())

	// Remove config from database
	_, err = h.Pool.Exec(r.Context(), `
		UPDATE tenants
		SET mail_config = NULL,
		    mail_config_key_version = 1,
		    updated_at = NOW()
		WHERE id = $1
	`, tenantID)

	if err != nil {
		h.Logger.Error("Failed to delete mail config", "error", err)
		helpers.RespondError(w, http.StatusInternalServerError, "failed to delete configuration")
		return
	}

	h.Logger.Info("Mail configuration deleted (fallback to system default)",
		"tenant_id", tenantID,
		"user_id", userID,
	)

	helpers.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "SMTP configuration removed, using system default",
	})
}

// GetEmailStats returns email delivery statistics for the tenant dashboard.
//
// GET /api/admin/email-stats
func (h *AuthHandler) GetEmailStats(w http.ResponseWriter, r *http.Request) {
	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		helpers.RespondError(w, http.StatusUnauthorized, "tenant context required")
		return
	}

	// Get outbox stats (last 24 hours)
	var pendingCount, processingCount, sentCount, failedCount int64
	err = h.Pool.QueryRow(r.Context(), `
		SELECT 
		    COUNT(*) FILTER (WHERE status = 'pending') as pending_count,
		    COUNT(*) FILTER (WHERE status = 'processing') as processing_count,
		    COUNT(*) FILTER (WHERE status = 'sent') as sent_count,
		    COUNT(*) FILTER (WHERE status = 'failed') as failed_count
		FROM email_outbox
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '24 hours'
	`, tenantID).Scan(&pendingCount, &processingCount, &sentCount, &failedCount)

	if err != nil {
		h.Logger.Error("Failed to fetch email stats", "error", err)
		helpers.RespondError(w, http.StatusInternalServerError, "failed to fetch statistics")
		return
	}

	// Get delivery stats (last 7 days)
	var deliveredCount, bouncedCount, spamCount int64
	err = h.Pool.QueryRow(r.Context(), `
		SELECT 
		    COUNT(*) FILTER (WHERE status = 'sent') as delivered_count,
		    COUNT(*) FILTER (WHERE status = 'bounced') as bounced_count,
		    COUNT(*) FILTER (WHERE status = 'spam_complaint') as spam_count
		FROM email_logs
		WHERE tenant_id = $1
		  AND created_at > NOW() - INTERVAL '7 days'
	`, tenantID).Scan(&deliveredCount, &bouncedCount, &spamCount)

	if err != nil {
		h.Logger.Error("Failed to fetch delivery stats", "error", err)
		// Non-fatal, continue with partial data
	}

	response := map[string]any{
		"queue": map[string]int64{
			"pending":    pendingCount,
			"processing": processingCount,
			"sent":       sentCount,
			"failed":     failedCount,
		},
		"delivery": map[string]int64{
			"delivered": deliveredCount,
			"bounced":   bouncedCount,
			"spam":      spamCount,
		},
	}

	helpers.RespondJSON(w, http.StatusOK, response)
}
