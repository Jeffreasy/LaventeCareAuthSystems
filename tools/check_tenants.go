package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
)

func main() {
	// 1. Load Environment
	if err := godotenv.Load(".env.local"); err != nil {
		godotenv.Load()
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	// 2. Connect to DB
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer conn.Close(ctx)

	// 3. Query Tenants
	rows, err := conn.Query(ctx, "SELECT id, name, slug FROM tenants")
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}
	defer rows.Close()

	fmt.Println("--- EXISTING TENANTS ---")
	count := 0
	for rows.Next() {
		var id string // UUID as string
		var name, slug string
		if err := rows.Scan(&id, &name, &slug); err != nil {
			log.Fatalf("Scan failed: %v", err)
		}
		fmt.Printf("ID: %s | Slug: %s | Name: %s\n", id, slug, name)
		count++
	}

	if count == 0 {
		fmt.Println("No tenants found! The database is likely empty.")
	}
}
