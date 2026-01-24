package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/api"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/audit"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/notify"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/Jeffreasy/LaventeCareAuthSystems/pkg/logger"
	"github.com/getsentry/sentry-go"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}

	// 1. Setup Global Logger
	log := logger.Setup(env)
	log.Info("application_startup", "env", env)

	// 2. Setup Sentry
	sentryDSN := os.Getenv("SENTRY_DSN")
	if sentryDSN != "" {
		err := sentry.Init(sentry.ClientOptions{
			Dsn:              sentryDSN,
			TracesSampleRate: 1.0,
			Environment:      env,
		})
		if err != nil {
			log.Error("sentry_init_failed", "error", err)
		} else {
			defer sentry.Flush(2 * time.Second)
			log.Info("sentry_initialized")
		}
	} else {
		log.Warn("sentry_dsn_missing", "details", "skipping_init")
	}

	// 3. Connect to Database
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Default to docker-compose credentials for dev experience
		dbURL = "postgres://user:password@localhost:5432/laventecare?sslmode=disable"
		log.Warn("database_url_default", "url", dbURL)
	}

	ctx := context.Background()
	poolConfig, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		log.Error("database_url_parse_failed", "error", err)
		os.Exit(1)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		log.Error("database_pool_create_failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Error("database_ping_failed", "error", err)
		os.Exit(1)
	}
	log.Info("database_connected")

	// 4. Initialize Sqlc Queries
	queries := db.New(pool)

	// 5. Initialize Auth Dependencies
	// In production, load JWT secret from env var
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "super-secret-dev-key"
		log.Warn("jwt_secret_default", "details", "dev_mode_enabled")
	}

	hasher := auth.NewBcryptHasher()
	tokenProvider := auth.NewJWTProvider(jwtSecret)

	// Email Sender (Dev Mode)
	emailSender := &notify.DevMailer{Logger: log}

	// MFA Service
	mfaService := auth.NewMFAService("LaventeCare")

	// Auth Config
	authConfig := auth.AuthConfig{
		AllowPublicRegistration: true, // Default to true for now
		DefaultAppURL:           os.Getenv("APP_URL"),
	}
	if authConfig.DefaultAppURL == "" {
		authConfig.DefaultAppURL = "https://auth.laventecare.nl"
	}

	// Audit Service
	auditLogger := audit.NewDBLogger(queries, log)

	authService := auth.NewAuthService(authConfig, pool, queries, hasher, tokenProvider, mfaService, auditLogger, emailSender)

	// 6. Setup HTTP Server
	server := api.NewServer(queries, authService, tokenProvider)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      server.Router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// 7. Start Server with Graceful Shutdown
	// "Anti-Gravity Law: Race Conditions are Fatal."
	// We must ensure database connections and requests are closed cleanly.

	serverErrors := make(chan error, 1)

	go func() {
		log.Info("server_listening", "port", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrors <- err
		}
	}()

	// 8. Block for Shutdown Signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Error("server_startup_failed", "error", err)
		os.Exit(1)

	case sig := <-shutdown:
		log.Info("shutdown_signal_received", "signal", sig)

		// Create shutdown context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second) // 20s allows for long DB queries to finish
		defer cancel()

		// Shutdown HTTP Server
		if err := srv.Shutdown(ctx); err != nil {
			log.Error("graceful_shutdown_failed", "error", err)
			if err := srv.Close(); err != nil {
				log.Error("server_force_close_failed", "error", err)
			}
		}

		// Explicitly close pool to ensure connection draining
		pool.Close()
		log.Info("database_pool_closed")

		log.Info("server_shutdown_complete")
		return // Exit main
	}
}
