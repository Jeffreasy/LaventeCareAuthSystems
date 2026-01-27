// Package main implements the email worker daemon.
// This background process polls the email_outbox table and sends emails via SMTP.
//
// Key Features:
// - Async processing (doesn't block HTTP requests)
// - Exponential backoff retry (5m, 10m, 20m)
// - Worker isolation (15s timeout per email prevents starvation)
// - SSRF protection (validates hosts on every send, not just config time)
// - Audit logging (writes to email_logs table)
//
// Security:
// - Only this process decrypts SMTP passwords (never exposed to API)
// - Uses FOR UPDATE SKIP LOCKED (prevents race conditions)
// - Validates tenants.mail_config on every send
//
// Usage:
//
//	go run cmd/emailworker/main.go
//
// Environment Variables:
//
//	DATABASE_URL - PostgreSQL connection string
//	TENANT_SECRET_KEY - AES-256 master key (32 bytes hex)
//	EMAIL_WORKER_INTERVAL - Poll interval (default: 5s)
//	EMAIL_WORKER_BATCH_SIZE - Max emails per poll (default: 10)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/config"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/mailer"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// 1. Setup logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	logger.Info("Email worker starting...")

	// 2. Load config
	cfg := config.Load()

	// 3. Connect to database
	pool, err := storage.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	// 4. Verify encryption key is configured
	if os.Getenv("TENANT_SECRET_KEY") == "" {
		log.Fatal("TENANT_SECRET_KEY not set (required for SMTP password decryption)")
	}

	// 5. Configuration
	pollInterval := getEnvDuration("EMAIL_WORKER_INTERVAL", 5*time.Second)
	batchSize := getEnvInt("EMAIL_WORKER_BATCH_SIZE", 10)

	logger.Info("Worker configured",
		"poll_interval", pollInterval,
		"batch_size", batchSize,
	)

	// 6. Start worker loop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Shutdown signal received, draining queue...")
		cancel()
	}()

	// Main worker loop
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	logger.Info("📧 Email Worker started, polling for emails...")

	for {
		select {
		case <-ctx.Done():
			logger.Info("Worker stopped")
			return

		case <-ticker.C:
			if err := processQueue(ctx, pool, logger, batchSize); err != nil {
				logger.Error("Queue processing error", "error", err)
			}
		}
	}
}

// processQueue fetches pending emails and processes them.
// Uses FOR UPDATE SKIP LOCKED to prevent race conditions between workers.
func processQueue(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, batchSize int) error {
	// Fetch pending emails (uses FOR UPDATE SKIP LOCKED for concurrency)
	rows, err := pool.Query(ctx, `
		SELECT id, tenant_id, payload, retry_count
		FROM email_outbox
		WHERE status = 'pending'
		  AND next_retry_at <= NOW()
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`, batchSize)

	if err != nil {
		return err
	}
	defer rows.Close()

	emailCount := 0

	for rows.Next() {
		var (
			id          uuid.UUID
			tenantID    uuid.UUID
			payloadJSON []byte
			retryCount  int
		)

		if err := rows.Scan(&id, &tenantID, &payloadJSON, &retryCount); err != nil {
			logger.Error("Failed to scan row", "error", err)
			continue
		}

		// Process email in isolated context with timeout (prevents starvation)
		emailCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := processEmail(emailCtx, pool, logger, id, tenantID, payloadJSON, retryCount)
		cancel()

		if err != nil {
			logger.Error("Email processing failed",
				"id", id,
				"tenant_id", tenantID,
				"retry_count", retryCount,
				"error", err,
			)
		}

		emailCount++
	}

	if emailCount > 0 {
		logger.Info("Processed email batch", "count", emailCount)
	}

	return nil
}

// processEmail sends a single email via SMTP.
// This function has a 15s timeout to prevent worker starvation.
func processEmail(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, id uuid.UUID, tenantID uuid.UUID, payloadJSON []byte, retryCount int) error {
	// 1. Mark as processing (prevents other workers from picking it up)
	_, err := pool.Exec(ctx, `
		UPDATE email_outbox
		SET status = 'processing',
		    processing_started_at = NOW()
		WHERE id = $1
	`, id)

	if err != nil {
		return err
	}

	// 2. Deserialize payload
	var payload mailer.EmailPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		markFailed(ctx, pool, id, "invalid payload JSON: "+err.Error())
		return err
	}

	// 3. Load tenant SMTP configuration
	smtpConfig, keyVersion, err := loadTenantSMTPConfig(ctx, pool, tenantID)
	if err != nil {
		// No SMTP config → use system default (fallback)
		logger.Warn("No tenant SMTP config, using system default",
			"tenant_id", tenantID,
		)
		smtpConfig = getSystemDefaultSMTPConfig()
		keyVersion = 1
	}

	// 4. Create SMTP provider
	provider, err := mailer.NewSMTPProvider(smtpConfig, keyVersion)
	if err != nil {
		markFailed(ctx, pool, id, "invalid SMTP config: "+err.Error())
		return err
	}

	// 5. Send email (SSRF protection happens inside Send())
	providerMsgID, err := provider.Send(ctx, payload)
	if err != nil {
		// Check if timeout
		if ctx.Err() == context.DeadlineExceeded {
			markFailed(ctx, pool, id, "SMTP timeout (slow server)")
			return err
		}

		// Other error
		markFailed(ctx, pool, id, err.Error())
		return err
	}

	// 6. Create audit log
	logID, err := mailer.CreateEmailLog(ctx, pool, payload, "sent", providerMsgID, "")
	if err != nil {
		logger.Error("Failed to create email log", "error", err)
		// Don't fail the send - email was delivered
	}

	// 7. Mark as sent
	_, err = pool.Exec(ctx, `
		UPDATE email_outbox
		SET status = 'sent',
		    processed_at = NOW(),
		    email_log_id = $2
		WHERE id = $1
	`, id, logID)

	if err != nil {
		return err
	}

	logger.Info("Email sent successfully",
		"id", id,
		"tenant_id", tenantID,
		"template", payload.Template,
		"to_hash", mailer.HashRecipient(payload.To),
		"provider_msg_id", providerMsgID,
	)

	return nil
}

// loadTenantSMTPConfig fetches the tenant's SMTP configuration from the database.
func loadTenantSMTPConfig(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID) (mailer.SMTPConfig, int, error) {
	var (
		configJSON []byte
		keyVersion int
	)

	err := pool.QueryRow(ctx, `
		SELECT mail_config, mail_config_key_version
		FROM tenants
		WHERE id = $1 AND mail_config IS NOT NULL
	`, tenantID).Scan(&configJSON, &keyVersion)

	if err != nil {
		return mailer.SMTPConfig{}, 0, err
	}

	var config mailer.SMTPConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return mailer.SMTPConfig{}, 0, err
	}

	return config, keyVersion, nil
}

// getSystemDefaultSMTPConfig returns fallback SMTP config from environment.
// Used when tenant doesn't have custom SMTP configured.
func getSystemDefaultSMTPConfig() mailer.SMTPConfig {
	return mailer.SMTPConfig{
		Host:          os.Getenv("SMTP_HOST"),
		Port:          getEnvInt("SMTP_PORT", 587),
		User:          os.Getenv("SMTP_USER"),
		PassEncrypted: "enc:" + os.Getenv("SMTP_PASS_ENCRYPTED"), // Assume already encrypted
		From:          os.Getenv("SMTP_FROM"),
		TLSMode:       os.Getenv("SMTP_TLS_MODE"),
	}
}

// markFailed marks an email as failed and schedules retry with exponential backoff.
func markFailed(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID, errorMsg string) {
	_, err := pool.Exec(ctx, `
		UPDATE email_outbox
		SET status = CASE
		        WHEN retry_count >= max_retries THEN 'failed'
		        ELSE 'pending'
		    END,
		    retry_count = retry_count + 1,
		    last_error = $2,
		    next_retry_at = CASE
		        WHEN retry_count >= max_retries THEN NULL
		        ELSE NOW() + (POWER(2, retry_count) * INTERVAL '5 minutes')
		    END
		WHERE id = $1
	`, id, errorMsg)

	if err != nil {
		slog.Error("Failed to mark email as failed", "id", id, "error", err)
	}
}

// Helper functions for environment variables
func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}

	dur, err := time.ParseDuration(val)
	if err != nil {
		return defaultVal
	}

	return dur
}

func getEnvInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}

	var i int
	if _, err := fmt.Sscanf(val, "%d", &i); err != nil {
		return defaultVal
	}

	return i
}
