package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"unicode/utf8"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// AuthHandler wraps the AuthService and provides HTTP handlers.
type AuthHandler struct {
	service *auth.AuthService
}

func NewAuthHandler(service *auth.AuthService) *AuthHandler {
	return &AuthHandler{service: service}
}

// RegisterRequest defines the expected JSON body for registration.
type RegisterRequest struct {
	Email    string    `json:"email"`
	Password string    `json:"password"`
	FullName string    `json:"full_name"`
	TenantID uuid.UUID `json:"tenant_id"`       // Optional
	Token    string    `json:"token,omitempty"` // Invite Token
}

func (req *RegisterRequest) Validate() error {
	if _, err := mail.ParseAddress(req.Email); err != nil {
		return fmt.Errorf("invalid email format")
	}
	if utf8.RuneCountInString(req.Password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	if len(req.FullName) > 100 {
		return fmt.Errorf("full name too long (max 100 chars)")
	}
	return nil
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	// Anti-Gravity Law 1: Input is Toxic. Enforce Content-Type.
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // Anti-Gravity Law 1: Input is Toxic

	if err := dec.Decode(&req); err != nil {
		slog.Warn("Register: Invalid JSON", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		slog.Warn("Register: Validation Failed", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest) // Validation errors are safe, but logging ensures visibility
		return
	}

	input := auth.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
		FullName: req.FullName,
		TenantID: req.TenantID,
		Token:    req.Token,
	}

	user, err := h.service.Register(r.Context(), input)
	if err != nil {
		// Anti-Gravity Law 2: Silence is Golden. Log trace, return generic.
		slog.Error("Register: Internal Error", "error", err)
		http.Error(w, "Registration failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	// Don't return the full user model if it contains anything sensitive (though it shouldn't)
	json.NewEncoder(w).Encode(user)
}

// LoginRequest defines the expected JSON body for login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (req *LoginRequest) Validate() error {
	if req.Email == "" || req.Password == "" {
		return fmt.Errorf("email and password required")
	}
	return nil
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	// Anti-Gravity Law 1: Input is Toxic. Enforce Content-Type.
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		slog.Warn("Login: Invalid JSON", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		// Validations are business logic, safe(r) to return, but let's log
		slog.Warn("Login: Validation Failed", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	input := auth.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		IP:        helpers.GetRealIP(r),
		UserAgent: r.UserAgent(),
	}

	result, err := h.service.Login(r.Context(), input)
	if err != nil {
		// Law 2: Silence is Golden. Do not reveal if user exists or password is wrong.
		// Note: h.service.Login already returns generic ErrInvalidCredentials, but we log here.
		slog.Warn("Login: Failed Attempt", "email", req.Email, "error", err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// MFA Verification Request
type VerifyMFARequest struct {
	UserID uuid.UUID `json:"user_id"` // Returned from Login step 1
	Code   string    `json:"code"`
}

func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	var req VerifyMFARequest
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("MFA Verify: Invalid JSON", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
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
		http.Error(w, "Invalid request body", http.StatusBadRequest)
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
		http.Error(w, "Invalid request body", http.StatusBadRequest)
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
		http.Error(w, "Invalid request body", http.StatusBadRequest)
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

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// 1. Get Refresh Token from Cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		// Already logged out or no session
		h.clearCookies(w)
		w.WriteHeader(http.StatusOK)
		return
	}

	// 2. Revoke in DB (Fire & Forget)
	_ = h.service.Logout(r.Context(), cookie.Value)

	// 3. Clear Cookies
	h.clearCookies(w)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out"})
}

// Refresh Token (Silent Refresh)
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// 1. Get Cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "No session", http.StatusUnauthorized)
		return
	}

	// 2. Metadata
	ip := helpers.GetRealIP(r)
	ua := r.UserAgent()

	// 3. Call Service
	result, err := h.service.RefreshSession(r.Context(), cookie.Value, ip, ua)
	if err != nil {
		// Log warning (possible reuse attack)
		slog.Warn("Refresh failed", "error", err)
		// Clear cookies on failure to force re-login
		h.clearCookies(w)
		http.Error(w, "Refresh failed", http.StatusUnauthorized)
		return
	}

	// 4. Set New Cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token", // Optional if using Header only, but usually symmetric
		Value:    result.AccessToken,
		Path:     "/",
		MaxAge:   900, // 15 min
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    result.RefreshToken,
		Path:     "/api/v1/auth",
		MaxAge:   604800, // 7 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// 5. Return Access Token (for memory client)
	json.NewEncoder(w).Encode(result)
}

func (h *AuthHandler) clearCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true, // Should be config driven
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/api/v1/auth", // Match the path used in Login? Defaulting to / for now to be safe
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

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
		http.Error(w, "Invalid request body", http.StatusBadRequest)
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
		http.Error(w, "Invalid request body", http.StatusBadRequest)
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

// Me returns the Session Rehydration data (Who Am I).
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	// 1. Extract IDs from Context (strictly typed)
	userID, err := customMiddleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tenantID, err := customMiddleware.GetTenantID(r.Context())
	if err != nil {
		http.Error(w, "Tenant Context Required", http.StatusBadRequest)
		return
	}

	// 2. Query via Service
	ctxInfo, err := h.service.GetUserContext(r.Context(), userID, tenantID)
	if err != nil {
		slog.Warn("Me: Context lookup failed", "user", userID, "tenant", tenantID, "error", err)
		// Return 401 to trigger frontend re-login if session is technically valid but db constraint fails (e.g. removed from tenant)
		http.Error(w, "Session invalid for this context", http.StatusUnauthorized)
		return
	}

	// 3. Return Safe JSON
	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":        ctxInfo.ID,
			"email":     ctxInfo.Email,
			"full_name": ctxInfo.FullName.String, // Handle pgtype.Text
			"role":      ctxInfo.Role,
		},
		"tenant": map[string]interface{}{
			"id":   ctxInfo.TenantID,
			"slug": ctxInfo.TenantSlug,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
