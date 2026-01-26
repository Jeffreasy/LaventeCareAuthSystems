//go:build ignore

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Println("DATABASE_URL not set")
		os.Exit(1)
	}

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	rows, err := pool.Query(context.Background(), "SELECT id, name, slug FROM tenants")
	if err != nil {
		fmt.Printf("Query failed: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	fmt.Println("=== Available Tenants ===")
	for rows.Next() {
		var id, name, slug string
		if err := rows.Scan(&id, &name, &slug); err != nil {
			continue
		}
		fmt.Printf("ID:   %s\nName: %s\nSlug: %s\n\n", id, name, slug)
	}
}
