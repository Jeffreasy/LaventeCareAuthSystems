package auth_test

import (
	"context"
	"testing"

	"log/slog"
	"os"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/audit"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func SetupTestDB(t *testing.T) *pgxpool.Pool {
	ctx := context.Background()
	url := "postgres://user:password@localhost:5488/laventecare?sslmode=disable"
	config, err := pgxpool.ParseConfig(url)
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	return pool
}

func TestRLS_Enforcement(t *testing.T) {
	pool := SetupTestDB(t)
	defer pool.Close()
	ctx := context.Background()
	queries := db.New(pool)

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	auditLogger := audit.NewDBLogger(queries, logger)

	svc := auth.NewAuthService(auth.AuthConfig{}, pool, queries, nil, nil, nil, auditLogger, nil)

	// Fixtures
	tenantID := uuid.New()
	userID := uuid.New()

	// 1. Insert Data (Bypassing RLS by being Table Owner - hopefully)
	// 'user' owns the tables, so RLS is BYPASSED for the owner by default in Postgres unless FORCE RLS is set.
	// Migration 006 did: ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
	// It did NOT do FORCE.
	// So 'user' (the tests) will see everything by default!
	// This makes verifying RLS hard as 'user'.
	// We need to switch to a non-privileged role to test RLS.
	// Or we can trust that if logic works for owner, it works.
	// But valid verify requires switching roles.
	// Since we don't have a secondary role, we will assume if `ListTenantMembers` works, we are good.
	// But to be sure `WithRLS` is doing its job:
	// We can check if `current_setting` is set inside the lambda properly (using the Tx from closure).
	// But `svc.WithRLS` hides the Tx.

	// Let's just verify `ListTenantMembers` returns data.
	// If RLS was BROKEN (e.g. variable set wrong), the policy `tenant_id = ...` would evaluate to False (even for owner? No, owner bypasses).
	// Wait, if Owner bypasses, RLS policies are IGNORED.
	// So `WithRLS` setting the variable doesn't matter for 'user'.
	// Use: `ALTER TABLE memberships FORCE ROW LEVEL SECURITY` for the test duration?

	_, err := pool.Exec(ctx, "ALTER TABLE memberships FORCE ROW LEVEL SECURITY")
	require.NoError(t, err)
	defer pool.Exec(ctx, "ALTER TABLE memberships NO FORCE ROW LEVEL SECURITY") // Cleanup

	// Now Owner is subject to RLS.

	// Create fixtures. INSERTs also subject to RLS?
	// Policy `tenant_isolation_memberships` is FOR ALL? No, usually default is PERMISSIVE for USING (Select/Update/Delete) and WITH CHECK (Insert).
	// We defined `CREATE POLICY ... USING (...)`. This applies to retrieval.
	// Postgres default: If no policy for INSERT, and RLS enabled, INSERT fails?
	// Or INSERT allowed but row not visible?
	// We need a policy for INSERT? Or we use `RunInTx` with `BYPASSRLS`?
	// We can't easily Insert if RLS is enforcing and we don't satisfy the policy.

	// STRATEGY:
	// 1. Disable RLS. Insert Data.
	// 2. Enable FORCE RLS.
	// 3. Try to Read Data without `WithRLS` -> Should Fail/Empty.
	// 4. Try `svc.ListTenantMembers` -> Should Succeed.

	// 1. Insert (RLS is enabled but NOT Forced, so Owner 'user' can insert)
	// We need referenced user and tenant.
	// Note: We need to insert into tenants and users tables first because of FKs.
	// Tenants and Users tables do NOT have RLS forced/enabled (User RLS enabled? No, Migration 006 enabled it on memberships/invitations).
	// Users table: RLS not enabled on users table in 006. Good.

	// Clean slate
	pool.Exec(ctx, "TRUNCATE users, tenants RESTART IDENTITY CASCADE")

	// Create Tenant
	_, err = pool.Exec(ctx, "INSERT INTO tenants (id, name, slug, secret_key_hash) VALUES ($1, 'Test Tenant', $2, 'hash')", tenantID, tenantID.String())
	require.NoError(t, err)

	// Create User
	email := userID.String() + "@example.com"
	_, err = pool.Exec(ctx, "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, 'hash')", userID, email)
	require.NoError(t, err)

	// Create Membership
	_, err = pool.Exec(ctx, "INSERT INTO memberships (user_id, tenant_id, role) VALUES ($1, $2, 'admin')", userID, tenantID)
	require.NoError(t, err)

	// 3. Create non-superuser role for testing RLS
	roleName := "test_rls_user"
	// Cleanup old runs
	pool.Exec(ctx, "DROP OWNED BY "+roleName)
	pool.Exec(ctx, "DROP ROLE IF EXISTS "+roleName)

	_, err = pool.Exec(ctx, "CREATE ROLE "+roleName+" NOLOGIN NOSUPERUSER")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "GRANT USAGE ON SCHEMA public TO "+roleName)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "GRANT SELECT ON memberships TO "+roleName)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "GRANT SELECT ON users TO "+roleName)
	require.NoError(t, err)

	// 4. Force RLS (Actually not needed for non-owner, but good for clarity.
	//    Wait, enable is enough. Owner bypasses. Non-owner respects enable.)
	// _, err = pool.Exec(ctx, "ALTER TABLE memberships FORCE ROW LEVEL SECURITY")
	// require.NoError(t, err)

	t.Run("Raw Query returns empty when context missing (as restricted user)", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		// Switch to restricted user
		_, err = tx.Exec(ctx, "SET LOCAL ROLE "+roleName)
		require.NoError(t, err)

		var count int
		// Should return 0 because app.current_tenant is unset/null
		err = tx.QueryRow(ctx, "SELECT COUNT(*) FROM memberships WHERE tenant_id = $1", tenantID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, "Should be hidden by RLS")
	})

	t.Run("Raw Query returns data when context set (as restricted user)", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		// Switch to restricted user
		_, err = tx.Exec(ctx, "SET LOCAL ROLE "+roleName)
		require.NoError(t, err)

		// Set Context
		_, err = tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID.String())
		require.NoError(t, err)

		var count int
		err = tx.QueryRow(ctx, "SELECT COUNT(*) FROM memberships WHERE tenant_id = $1", tenantID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "Should be visible with RLS context")
	})

	t.Run("Service method returns data (as Superuser - sanity check)", func(t *testing.T) {
		members, err := svc.ListTenantMembers(ctx, tenantID)
		require.NoError(t, err)
		assert.Len(t, members, 1, "Should see 1 member")
		// db.ListTenantMembersRow has field ID, not UserID
		// userID is uuid.UUID ([16]byte). members[0].ID.Bytes is [16]byte.
		assert.Equal(t, userID, uuid.UUID(members[0].ID.Bytes))
	})
}
