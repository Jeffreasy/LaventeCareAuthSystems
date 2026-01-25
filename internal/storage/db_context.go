package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithTenantContext executes a function within a PostgreSQL transaction
// with the app.current_tenant session variable set for Row Level Security.
//
// This pattern ensures that all RLS policies evaluated within the transaction
// respect the tenant isolation boundary. The session variable is automatically
// cleared when the transaction ends (SET LOCAL is transaction-scoped).
//
// Example usage:
//
//	err := storage.WithTenantContext(ctx, pool, tenantID, func(tx pgx.Tx) error {
//	    queries := db.New(tx)
//	    return queries.GetMemberships(ctx, userID)
//	})
func WithTenantContext(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, fn func(tx pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) // Rollback is safe to call even after Commit

	// Set the session variable for RLS policies
	// Migration 006 policies use: NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID
	_, err = tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set tenant context: %w", err)
	}

	// Execute the user-provided function
	if err := fn(tx); err != nil {
		return err // Transaction will rollback via defer
	}

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// WithoutRLS executes a function within a transaction that bypasses Row Level Security.
//
// This is intended for system-level operations such as:
// - Audit log writes (need to insert regardless of tenant context)
// - Background workers (Janitor cleaning expired tokens across all tenants)
// - Admin operations that require cross-tenant visibility
//
// SECURITY WARNING: Use this sparingly. Most application logic should use WithTenantContext.
//
// Example usage:
//
//	err := storage.WithoutRLS(ctx, pool, func(tx pgx.Tx) error {
//	    queries := db.New(tx)
//	    return queries.CreateAuditLog(ctx, params)
//	})
func WithoutRLS(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// No SET LOCAL. RLS policies will evaluate current_setting('app.current_tenant') as empty/NULL.
	// For table owners (superuser 'user'), RLS is bypassed by default unless FORCE RLS is set.
	// For non-privileged roles, rows will be hidden unless policies explicitly allow NULL tenant.
	// This works because:
	// 1. Audit writes use this pattern (owner bypass)
	// 2. System operations run as owner
	// Future: Consider explicit 'SET LOCAL app.bypass_rls = true' for clarity

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ExecInTenantContext is a convenience wrapper for single statement execution
// with tenant context. For complex operations, use WithTenantContext directly.
func ExecInTenantContext(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, sql string, args ...interface{}) error {
	return WithTenantContext(ctx, pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}
