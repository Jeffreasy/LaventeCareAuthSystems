package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"unicode/utf8"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/helpers"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
	"github.com/google/uuid"
)

// MeResponse defines the strictly typed response for /me endpoint.
type MeResponse struct {
	User   MeUser   `json:"user"`
	Tenant MeTenant `json:"tenant"`
}

type MeUser struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	FullName string    `json:"full_name"`
	Role     string    `json:"role"`
}

type MeTenant struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
}

// RegisterRequest defines the expected JSON body for registration.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
	// TenantID removed: Strict Tenant Isolation requires usage of X-Tenant-ID Header
	Token string `json:"token,omitempty"` // Invite Token
}

func (req *RegisterRequest) Validate() error {
	if req.Token != "" {
		// If token is present, ensure it has reasonable length/format
		if len(req.Token) < 10 {
			return fmt.Errorf("invalid invite token format")
		}
	}
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
	// Helpers now enforce Anti-Gravity Law 1 (Content-Type + DisallowUnknownFields)
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("Register: Invalid Request Body", "error", err)
		http.Error(w, "Invalid request body format", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		slog.Warn("Register: Validation Failed", "error", err)
		http.Error(w, "Validation failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Resolve Tenant Context
	// Optimization: If Token is present, Service *could* infer tenant,
	// but enforcing Context consistency is safer.
	tenantID, err := middleware.GetTenantID(r.Context())
	if err != nil && req.Token == "" {
		// Only required if NOT using an invite (Invites carry their own context, theoretically)
		// But in strict mode, we want the endpoint to match the tenant.
		slog.Warn("Register: Missing Tenant Context", "ip", r.RemoteAddr)
		http.Error(w, "Tenant ID Header required", http.StatusBadRequest)
		return
	}

	input := auth.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
		FullName: req.FullName,
		TenantID: tenantID, // Secured from Context
		Token:    req.Token,
	}

	user, err := h.service.Register(r.Context(), input)
	if err != nil {
		// Anti-Gravity Law 2: Silence is Golden. Log trace, return generic.
		slog.Error("Register: Internal Error", "error", err)
		http.Error(w, "Registration failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
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
	if err := helpers.DecodeJSON(r, &req); err != nil {
		slog.Warn("Login: Invalid Request Body", "ip", helpers.GetRealIP(r), "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		slog.Warn("Login: Validation Failed", "ip", helpers.GetRealIP(r), "error", err)
		http.Error(w, "Validation failed", http.StatusBadRequest)
		return
	}

	// Anti-Gravity Security: Enforce Tenant Context
	tenantID, err := middleware.GetTenantID(r.Context())
	if err != nil {
		slog.Warn("Login: Missing Tenant Context", "ip", helpers.GetRealIP(r))
		http.Error(w, "Tenant Context Required", http.StatusBadRequest)
		return
	}

	input := auth.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		TenantID:  tenantID, // Enforce Scope
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

	// ✅ SECURE: Set HttpOnly cookies (XSS protection)
	// Tokens are NEVER exposed to JavaScript
	// CONFIG: Cross-Origin Support (Localhost -> Render) requires SameSite=None; Secure
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    result.AccessToken,
		Path:     "/",
		MaxAge:   900, // 15 min
		HttpOnly: true,
		Secure:   true,                  // Required for SameSite=None
		SameSite: http.SameSiteNoneMode, // Required for Cross-Origin AJAX
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    result.RefreshToken,
		Path:     "/",
		MaxAge:   604800, // 7 days
		HttpOnly: true,
		Secure:   true,                  // Required for SameSite=None
		SameSite: http.SameSiteNoneMode, // Required for Cross-Origin AJAX
	})

	// ✅ Return user data only (NO tokens in JSON)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": result.User,
	})
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
		Name:     "access_token",
		Value:    result.AccessToken,
		Path:     "/",
		MaxAge:   900, // 15 min
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    result.RefreshToken,
		Path:     "/",
		MaxAge:   604800, // 7 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	// 5. Return Access Token (for memory client)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out"})
}

// GetOIDCConfig serves the OpenID Configuration for OIDC discovery.
func (h *AuthHandler) GetOIDCConfig(w http.ResponseWriter, r *http.Request) {
	baseURL := "https://laventecareauthsystems.onrender.com"

	config := map[string]interface{}{
		"issuer":                                baseURL,
		"jwks_uri":                              baseURL + "/.well-known/jwks.json",
		"authorization_endpoint":                baseURL + "/api/v1/auth/authorize",
		"token_endpoint":                        baseURL + "/api/v1/auth/token",
		"userinfo_endpoint":                     baseURL + "/api/v1/me",
		"response_types_supported":              []string{"code", "token", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// GetJWKS serves the JSON Web Key Set for OIDC verification.
func (h *AuthHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := h.service.GetJWKS()
	if err != nil {
		slog.Error("GetJWKS failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// Me returns the strictly typed Session Rehydration data (Who Am I).
// Security: Enforces strict Tenant Isolation via Middleware & Service Layer.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	// 1. Extract IDs from Context (strictly typed)
	userID, err := middleware.GetUserID(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tenantID, err := middleware.GetTenantID(r.Context())
	if err != nil {
		http.Error(w, "Tenant Context Required", http.StatusBadRequest)
		return
	}

	// 2. Query via Service (Strict Isolation)
	ctxInfo, err := h.service.GetUserContext(r.Context(), userID, tenantID)
	if err != nil {
		slog.Warn("Me: Context lookup failed", "user", userID, "tenant", tenantID, "error", err)
		http.Error(w, "Session invalid for this context", http.StatusUnauthorized)
		return
	}

	// 3. Return Strict Response
	response := MeResponse{
		User: MeUser{
			ID:       uuid.UUID(ctxInfo.ID.Bytes),
			Email:    ctxInfo.Email,
			FullName: ctxInfo.FullName.String, // Handle pgtype.Text safely
			Role:     ctxInfo.Role,
		},
		Tenant: MeTenant{
			ID:   uuid.UUID(ctxInfo.TenantID.Bytes),
			Slug: ctxInfo.TenantSlug,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
