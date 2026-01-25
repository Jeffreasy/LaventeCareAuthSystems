package storage_test

import (
	"context"
	"testing"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestPool(t *testing.T) *pgxpool.Pool {
	ctx := context.Background()
	url := "postgres://user:password@localhost:5488/laventecare?sslmode=disable"
	config, err := pgxpool.ParseConfig(url)
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	return pool
}

func TestWithTenantContext_SetsSessionVariable(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := uuid.New()

	err := storage.WithTenantContext(ctx, pool, tenantID, func(tx pgx.Tx) error {
		// Verify the session variable is set
		var value string
		err := tx.QueryRow(ctx, "SELECT current_setting('app.current_tenant', true)").Scan(&value)
		require.NoError(t, err)
		assert.Equal(t, tenantID.String(), value, "Session variable should be set to tenant ID")
		return nil
	})

	require.NoError(t, err)
}

func TestWithTenantContext_RollsBackOnError(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := uuid.New()

	// Clean slate
	pool.Exec(ctx, "DROP TABLE IF EXISTS test_rls_rollback")
	pool.Exec(ctx, "CREATE TABLE test_rls_rollback (id UUID PRIMARY KEY)")

	expectedErr := assert.AnError

	err := storage.WithTenantContext(ctx, pool, tenantID, func(tx pgx.Tx) error {
		// Insert a row
		_, err := tx.Exec(ctx, "INSERT INTO test_rls_rollback (id) VALUES ($1)", uuid.New())
		require.NoError(t, err)

		// Return error to trigger rollback
		return expectedErr
	})

	// Verify the error bubbled up
	assert.ErrorIs(t, err, expectedErr)

	// Verify the insert was rolled back
	var count int
	pool.QueryRow(ctx, "SELECT COUNT(*) FROM test_rls_rollback").Scan(&count)
	assert.Equal(t, 0, count, "Insert should have been rolled back")

	// Cleanup
	pool.Exec(ctx, "DROP TABLE test_rls_rollback")
}

func TestWithTenantContext_CommitsOnSuccess(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := uuid.New()
	testID := uuid.New()

	// Clean slate
	pool.Exec(ctx, "DROP TABLE IF EXISTS test_rls_commit")
	pool.Exec(ctx, "CREATE TABLE test_rls_commit (id UUID PRIMARY KEY)")

	err := storage.WithTenantContext(ctx, pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO test_rls_commit (id) VALUES ($1)", testID)
		return err
	})

	require.NoError(t, err)

	// Verify the insert was committed
	var foundID uuid.UUID
	err = pool.QueryRow(ctx, "SELECT id FROM test_rls_commit WHERE id = $1", testID).Scan(&foundID)
	require.NoError(t, err)
	assert.Equal(t, testID, foundID)

	// Cleanup
	pool.Exec(ctx, "DROP TABLE test_rls_commit")
}

func TestWithoutRLS_BypassesPolicies(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()
	ctx := context.Background()

	err := storage.WithoutRLS(ctx, pool, func(tx pgx.Tx) error {
		// Verify NO session variable is set (NULL/empty when not set)
		// Use COALESCE to convert NULL to empty string for comparison
		var value string
		err := tx.QueryRow(ctx, "SELECT COALESCE(current_setting('app.current_tenant', true), '')").Scan(&value)
		require.NoError(t, err)
		assert.Empty(t, value, "Session variable should NOT be set in WithoutRLS")
		return nil
	})

	require.NoError(t, err)
}

func TestExecInTenantContext_ConvenienceWrapper(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := uuid.New()

	// Clean slate
	pool.Exec(ctx, "DROP TABLE IF EXISTS test_exec_helper")
	pool.Exec(ctx, "CREATE TABLE test_exec_helper (id UUID PRIMARY KEY)")

	testID := uuid.New()

	// Use convenience wrapper
	err := storage.ExecInTenantContext(ctx, pool, tenantID,
		"INSERT INTO test_exec_helper (id) VALUES ($1)", testID)
	require.NoError(t, err)

	// Verify
	var foundID uuid.UUID
	pool.QueryRow(ctx, "SELECT id FROM test_exec_helper WHERE id = $1", testID).Scan(&foundID)
	assert.Equal(t, testID, foundID)

	// Cleanup
	pool.Exec(ctx, "DROP TABLE test_exec_helper")
}
