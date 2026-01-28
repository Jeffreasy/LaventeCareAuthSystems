package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	customMiddleware "github.com/Jeffreasy/LaventeCareAuthSystems/internal/api/middleware"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage"
	"github.com/google/uuid"
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

func TestTenantContext_NoHeader_PublicEndpoint(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()

	// Create middleware
	middleware := customMiddleware.TenantContext(pool)

	// Create test handler that verifies NO transaction is set
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := storage.GetTx(r.Context())
		assert.Nil(t, tx, "Transaction should be nil for requests without X-Tenant-ID header")
		w.WriteHeader(http.StatusOK)
	})

	// Create request WITHOUT X-Tenant-ID header
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	// Execute
	middleware(handler).ServeHTTP(rr, req)

	// Verify public endpoint worked
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestTenantContext_InvalidUUID_Returns400(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()

	middleware := customMiddleware.TenantContext(pool)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Handler should not be called for invalid UUID")
	})

	// Invalid UUID
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("X-Tenant-ID", "not-a-uuid")
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid Tenant ID")
}

func TestTenantContext_ValidTenant_SetsSessionVariable(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()

	tenantID := uuid.New()
	middleware := customMiddleware.TenantContext(pool)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify transaction is available
		tx := storage.GetTx(r.Context())
		require.NotNil(t, tx, "Transaction should be set for requests with X-Tenant-ID")

		// Verify session variable is set
		var value string
		err := tx.QueryRow(r.Context(), "SELECT current_setting('app.current_tenant', true)").Scan(&value)
		require.NoError(t, err)
		assert.Equal(t, tenantID.String(), value)

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestTenantContext_ValidTenant_CommitsOnSuccess(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()

	tenantID := uuid.New()
	testID := uuid.New()

	// Clean slate
	pool.Exec(context.Background(), "DROP TABLE IF EXISTS test_commit")
	pool.Exec(context.Background(), "CREATE TABLE test_commit (id UUID PRIMARY KEY)")

	middleware := customMiddleware.TenantContext(pool)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := storage.GetTx(r.Context())
		require.NotNil(t, tx)

		// Insert a row in the transaction
		_, err := tx.Exec(r.Context(), "INSERT INTO test_commit (id) VALUES ($1)", testID)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK) // Success status triggers commit
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/data", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify insert was committed
	var foundID uuid.UUID
	err := pool.QueryRow(context.Background(), "SELECT id FROM test_commit WHERE id = $1", testID).Scan(&foundID)
	require.NoError(t, err)
	assert.Equal(t, testID, foundID)

	// Cleanup
	pool.Exec(context.Background(), "DROP TABLE test_commit")
}

func TestTenantContext_HandlerError_RollsBack(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()

	tenantID := uuid.New()
	testID := uuid.New()

	// Clean slate
	pool.Exec(context.Background(), "DROP TABLE IF EXISTS test_rollback")
	pool.Exec(context.Background(), "CREATE TABLE test_rollback (id UUID PRIMARY KEY)")

	middleware := customMiddleware.TenantContext(pool)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := storage.GetTx(r.Context())
		require.NotNil(t, tx)

		// Insert a row
		_, err := tx.Exec(r.Context(), "INSERT INTO test_rollback (id) VALUES ($1)", testID)
		require.NoError(t, err)

		// Return error status (triggers rollback)
		http.Error(w, "Business logic error", http.StatusBadRequest)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/data", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Verify insert was rolled back
	var count int
	pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM test_rollback WHERE id = $1", testID).Scan(&count)
	assert.Equal(t, 0, count, "Insert should have been rolled back")

	// Cleanup
	pool.Exec(context.Background(), "DROP TABLE test_rollback")
}

func TestGetTx_ReturnsNilWhenNoTransaction(t *testing.T) {
	ctx := context.Background()
	tx := storage.GetTx(ctx)
	assert.Nil(t, tx)
}

func TestGetTx_ReturnsTransactionWhenSet(t *testing.T) {
	pool := setupTestPool(t)
	defer pool.Close()

	tenantID := uuid.New()
	middleware := customMiddleware.TenantContext(pool)

	var capturedTx interface{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := storage.GetTx(r.Context())
		capturedTx = tx
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	assert.NotNil(t, capturedTx, "Transaction should be available in context")
}
