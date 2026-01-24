package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/config"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
)

func main() {
	// 1. Init Logger & Config
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := config.Load()

	// 2. DB Connection
	pool, err := storage.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		logger.Error("Failed to connect to DB", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	queries := storage.New(pool)
	logger.Info("🧹 Janitor Worker Started", "interval", "1h")

	// 3. Scheduler (Elk uur)
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// 4. Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Directe run bij opstarten (zodat je meteen resultaat ziet in dev)
	runJanitor(context.Background(), queries, logger)

	for {
		select {
		case <-ticker.C:
			runJanitor(context.Background(), queries, logger)
		case <-quit:
			logger.Info("🛑 Janitor shutting down...")
			return
		}
	}
}

func runJanitor(ctx context.Context, q *db.Queries, logger *slog.Logger) {
	logger.Info("Running cleanup cycle...")

	// Refresh Tokens
	count, err := q.CleanExpiredRefreshTokens(ctx)
	if err != nil {
		logger.Error("Failed to clean refresh_tokens", "error", err)
	} else if count > 0 {
		logger.Info("Cleaned refresh_tokens", "deleted", count)
	}

	// Invitations
	count, err = q.CleanExpiredInvitations(ctx)
	if err != nil {
		logger.Error("Failed to clean invitations", "error", err)
	} else if count > 0 {
		logger.Info("Cleaned invitations", "deleted", count)
	}

	// Verification Tokens
	count, err = q.CleanExpiredVerificationTokens(ctx)
	if err != nil {
		logger.Error("Failed to clean verification_tokens", "error", err)
	} else if count > 0 {
		logger.Info("Cleaned verification_tokens", "deleted", count)
	}

	// MFA Codes
	count, err = q.CleanUsedMfaCodes(ctx)
	if err != nil {
		logger.Error("Failed to clean mfa_backup_codes", "error", err)
	} else if count > 0 {
		logger.Info("Cleaned mfa_backup_codes", "deleted", count)
	}
}
