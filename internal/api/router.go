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
	"github.com/jackc/pgx/v5/pgxpool"
)

type Server struct {
	Router *chi.Mux
	DB     *db.Queries
	Pool   *pgxpool.Pool // Database connection pool for health checks
	Auth   *auth.AuthService
	Logger *slog.Logger
}

func NewServer(pool *pgxpool.Pool, queries *db.Queries, authService *auth.AuthService, tokenProvider auth.TokenProvider) *Server {
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
	r.Use(customMiddleware.PanicRecovery) // Custom recovery with Sentry support

	// 4. Active Defense Middlewares
	limiter := customMiddleware.NewIPRateLimiter(5, 10) // 5 RPS, Burst 10
	r.Use(limiter.Middleware)

	// PHASE 50 RLS: TenantContext now requires pool for SET LOCAL transaction wrapping
	r.Use(customMiddleware.TenantContext(pool))
	// CSRF moved to protected routes only (public auth endpoints don't need it)

	// 5. Auth & RBAC Factories
	// We create factories for use in specific routes
	requireAuth := customMiddleware.AuthMiddleware(tokenProvider)
	requireRBAC := customMiddleware.RBACMiddleware()

	// Handlers
	authHandler := NewAuthHandler(authService, pool, slog.Default())
	iotHandler := NewIoTHandler(queries)

	// Initialize server early to use its methods
	server := &Server{
		Router: r,
		DB:     queries,
		Pool:   pool, // PHASE 50: Pool now set during initialization
		Auth:   authService,
		Logger: slog.Default(),
	}

	// Base Routes
	// Health check endpoint (used by Render for zero-downtime deployments)
	r.Get("/health", server.HealthHandler())

	// OIDC Endpoints (for Convex and other integrations)
	r.Get("/.well-known/openid-configuration", authHandler.GetOIDCConfig)
	r.Get("/.well-known/jwks.json", authHandler.GetJWKS)

	// API Group
	r.Route("/api/v1", func(r chi.Router) {

		// Public Routes
		r.Post("/auth/register", authHandler.Register)
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/logout", authHandler.Logout)

		// IoT Telemetry (Gatekeeper)
		r.Post("/iot/telemetry", iotHandler.HandleTelemetry)

		// MFA Verification (Public/Semi-Public)
		r.Post("/auth/mfa/verify", authHandler.VerifyMFA)
		r.Post("/auth/mfa/backup", authHandler.VerifyBackupCode)

		// Public Tenant Lookup (Phase 27)
		publicHandler := NewPublicHandler(queries)
		r.Get("/tenants/{slug}", publicHandler.GetTenantInfo)

		// Protected Routes
		r.Group(func(r chi.Router) {
			r.Use(requireAuth)
			r.Use(customMiddleware.CSRFMiddleware) // Apply CSRF to authenticated routes only

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

				// Mail Configuration Management (Email Gateway)
				r.Get("/mail-config", authHandler.GetMailConfig)
				r.Post("/mail-config", authHandler.UpdateMailConfig)
				r.Delete("/mail-config", authHandler.DeleteMailConfig)
				r.Get("/email-stats", authHandler.GetEmailStats)
			})
		})
	})

	return server
}
