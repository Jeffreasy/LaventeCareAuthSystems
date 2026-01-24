package api

import (
	"log/slog"
	"net/http"

	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	Router *chi.Mux
	DB     *db.Queries
	Auth   *auth.AuthService
	Logger *slog.Logger
}

func NewServer(queries *db.Queries, authService *auth.AuthService, tokenProvider auth.TokenProvider) *Server {
	r := chi.NewRouter()

	// 1. Core Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	// 2. Sentry Middleware (Must be before Panic Recovery to capture panics)
	sentryHandler := sentryhttp.New(sentryhttp.Options{
		Repanic: true,
	})
	r.Use(sentryHandler.Handle)

	// 3. Logger & Recovery
	r.Use(customMiddleware.RequestLogger) // Our custom slog logger
	r.Use(customMiddleware.RequestLogger) // Our custom slog logger
	r.Use(customMiddleware.PanicRecovery) // Custom recovery with Sentry support

	// 4. Active Defense Middlewares
	limiter := customMiddleware.NewIPRateLimiter(5, 10) // 5 RPS, Burst 10
	r.Use(limiter.Middleware)
	r.Use(customMiddleware.TenantContext)
	r.Use(customMiddleware.CSRFMiddleware) // Phase 15: Cookie Security

	// 5. Auth & RBAC Factories
	// We create factories for use in specific routes
	requireAuth := customMiddleware.AuthMiddleware(tokenProvider)
	requireRBAC := customMiddleware.RBACMiddleware()

	// Handlers
	authHandler := NewAuthHandler(authService)

	// Base Routes
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// API Group
	r.Route("/api/v1", func(r chi.Router) {

		// Public Routes
		r.Post("/auth/register", authHandler.Register)
		r.Post("/auth/login", authHandler.Login)

		// MFA Verification (Public/Semi-Public)
		r.Post("/auth/mfa/verify", authHandler.VerifyMFA)
		r.Post("/auth/mfa/backup", authHandler.VerifyBackupCode)

		// Public Tenant Lookup (Phase 27)
		publicHandler := NewPublicHandler(queries)
		r.Get("/tenants/{slug}", publicHandler.GetTenantInfo)

		// Protected Routes
		r.Group(func(r chi.Router) {
			r.Use(requireAuth)

			// Example: User Profile (Self)
			r.Get("/me", authHandler.Me) // Updated to use handler method

			// Session Management (Phase 17)
			r.Get("/auth/sessions", authHandler.GetSessions)
			r.Delete("/auth/sessions/{id}", authHandler.RevokeSession)

			// MFA Management (Phase 10 & 14)
			r.Post("/auth/mfa/setup", authHandler.SetupMFA)
			r.Post("/auth/mfa/activate", authHandler.ActivateMFA)

			// Email Change (Phase 19)
			r.Post("/auth/account/email/change", authHandler.RequestEmailChange)
			r.Post("/auth/account/email/confirm", authHandler.ConfirmEmailChange)

			// User Self-Service (Phase 26)
			r.Patch("/auth/profile", authHandler.UpdateProfile)
			r.Put("/auth/security/password", authHandler.ChangePassword)

			// Example: Admin Only Action
			r.Route("/admin", func(r chi.Router) {
				r.Use(requireRBAC("admin"))

				r.Delete("/tenants", func(w http.ResponseWriter, r *http.Request) {
					// This logic would delete the tenant in the current context
					w.Write([]byte("Tenant Deleted"))
				})

				// User Management (Phase 25)
				r.Get("/users", authHandler.ListUsers)
				r.Patch("/users/{userID}", authHandler.UpdateRole)
				r.Delete("/users/{userID}", authHandler.RemoveUser)

				// Invite User (Phase 16)
				r.Post("/users/invite", authHandler.InviteUser)
			})
		})
	})

	return &Server{
		Router: r,
		DB:     queries,
		Auth:   authService,
		Logger: slog.Default(),
	}
}
