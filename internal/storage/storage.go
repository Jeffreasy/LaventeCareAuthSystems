package storage

import (
	"context"
	"fmt"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPostgres creates a new connection pool to PostgreSQL.
func NewPostgres(dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Tweak config here if needed (MaxConns, etc.)

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to db: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping db: %w", err)
	}

	return pool, nil
}

// New wraps db.New to create queries from a DBTX (pool or tx).
// This matches the usage in cmd/control `queries := storage.New(pool)`.
func New(dbtx db.DBTX) *db.Queries {
	return db.New(dbtx)
}
