package audit_test

import (
	"context"
	"testing"

	"log/slog"
	"os"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/audit"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/notify"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func SetupServices(t *testing.T) (*pgxpool.Pool, *auth.AuthService, *db.Queries) {
	ctx := context.Background()
	url := "postgres://user:password@localhost:5488/laventecare?sslmode=disable"
	pool, err := pgxpool.New(ctx, url)
	require.NoError(t, err)

	queries := db.New(pool)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	auditLogger := audit.NewDBLogger(queries, logger)

	// Mock or real deps
	hasher := auth.NewBcryptHasher()
	tokenProvider := auth.NewJWTProvider("secret")
	mfa := auth.NewMFAService("Test")
	mail := &notify.DevMailer{Logger: logger}

	svc := auth.NewAuthService(auth.AuthConfig{AllowPublicRegistration: true}, pool, queries, hasher, tokenProvider, mfa, auditLogger, mail)

	return pool, svc, queries
}

func TestAuditLogIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	pool, svc, queries := SetupServices(t)
	defer pool.Close()
	ctx := context.Background()

	// Cleanup
	pool.Exec(ctx, "TRUNCATE users, audit_logs CASCADE")

	// 1. Register User (Public) -> Should Trigger Audit Log
	email := "audit_test@example.com"
	tenantID := uuid.New() // Will become default tenant

	// Create Tenant first to satisfy FK
	_, err := pool.Exec(ctx, "INSERT INTO tenants (id, name, slug, secret_key_hash) VALUES ($1, 'Audit Tenant', $2, 'hash')", tenantID, tenantID.String())
	require.NoError(t, err)

	_, err = svc.Register(ctx, auth.RegisterInput{
		Email:    email,
		Password: "Password123!",
		FullName: "Audit Tester",
		TenantID: tenantID,
	})
	require.NoError(t, err)

	// 2. Verify Audit Log Exists
	// We need a custom query to check audit logs since we only generated CreateAuditLog?
	// Ah, we added ListAuditLogs in audit.sql (Step 932).
	// But `sqlc generate` ran. So `ListAuditLogsByUser` should exist?
	// Let's check `audit.sql` content again.
	// Step 935 created `audit.sql` with `ListAuditLogsByTenant` and `ListAuditLogsByUser`.
	// So we can use `ListAuditLogsByTenant`.

	// Wait, Register (Public) sets TenantID to the input tenantID?
	// Yes, `Register` (Legacy Flow) sets `DefaultTenantID`.
	// The audit log in `Register` uses `defaultTenantUUID.Bytes`.

	t.Run("Verify Registration Audit Log", func(t *testing.T) {
		// Give it a moment? No, generic exec is synchronous.

		logs, err := queries.ListAuditLogsByTenant(ctx, db.ListAuditLogsByTenantParams{
			TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
			Limit:    10,
			Offset:   0,
		})
		require.NoError(t, err)

		require.NotEmpty(t, logs, "Should have audit logs")
		assert.Equal(t, "user.create.public", logs[0].Action)

		// Verify Actor is the user (Self registration)
		// We need UserID. We can get it from users table or by email.
		user, _ := queries.GetUserByEmail(ctx, email)
		assert.Equal(t, user.ID, logs[0].ActorID)
	})
}
