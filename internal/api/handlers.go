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
