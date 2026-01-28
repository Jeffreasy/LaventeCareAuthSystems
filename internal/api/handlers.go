package api

import (
	"log/slog"
	"net/http"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuthHandler wraps the AuthService and provides HTTP handlers.
type AuthHandler struct {
	service *auth.AuthService
	Pool    *pgxpool.Pool // For direct queries (mail config)
	Logger  *slog.Logger
}

func NewAuthHandler(service *auth.AuthService, pool *pgxpool.Pool, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		service: service,
		Pool:    pool,
		Logger:  logger,
	}
}

func (h *AuthHandler) clearCookies(w http.ResponseWriter) {
	// Must match existing attributes to overwrite/delete
	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	if v := accessCookie.String(); v != "" {
		w.Header().Add("Set-Cookie", v+"; Partitioned")
	}

	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/", // Reset to root path to ensure we catch it
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	if v := refreshCookie.String(); v != "" {
		w.Header().Add("Set-Cookie", v+"; Partitioned")
	}
}
