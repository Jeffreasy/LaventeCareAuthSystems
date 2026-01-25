package storage_test

import (
	"context"
	"testing"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func BenchmarkWithTenantContext(b *testing.B) {
	ctx := context.Background()
	url := "postgres://user:password@localhost:5488/laventecare?sslmode=disable"
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		b.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		b.Fatal(err)
	}
	defer pool.Close()

	tenantID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := storage.WithTenantContext(ctx, pool, tenantID, func(tx pgx.Tx) error {
			// Simulate a simple query
			var val int
			return tx.QueryRow(ctx, "SELECT 1").Scan(&val)
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWithoutContext(b *testing.B) {
	ctx := context.Background()
	url := "postgres://user:password@localhost:5488/laventecare?sslmode=disable"
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		b.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		b.Fatal(err)
	}
	defer pool.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			b.Fatal(err)
		}

		var val int
		err = tx.QueryRow(ctx, "SELECT 1").Scan(&val)
		if err != nil {
			tx.Rollback(ctx)
			b.Fatal(err)
		}

		err = tx.Commit(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWithoutRLS(b *testing.B) {
	ctx := context.Background()
	url := "postgres://user:password@localhost:5488/laventecare?sslmode=disable"
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		b.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		b.Fatal(err)
	}
	defer pool.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := storage.WithoutRLS(ctx, pool, func(tx pgx.Tx) error {
			var val int
			return tx.QueryRow(ctx, "SELECT 1").Scan(&val)
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
