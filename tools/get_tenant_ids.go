package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	// 1. Load Env
	if err := godotenv.Load(".env.local"); err != nil {
		if err := godotenv.Load(); err != nil {
			log.Println("Warning: No .env or .env.local found, using system env")
		}
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer pool.Close()

	queries := db.New(pool)

	slugs := []string{"dkl", "laventecare"}

	fmt.Println("\n✅  Tenant IDs Verification")
	fmt.Println("==================================================")

	for _, slug := range slugs {
		tenant, err := queries.GetTenantBySlug(ctx, slug)
		if err != nil {
			fmt.Printf("❌  %s: Not Found (%v)\n", slug, err)
			continue
		}
		// Assuming UUID bytes are standard 16 bytes
		uuidStr := fmt.Sprintf("%x-%x-%x-%x-%x",
			tenant.ID.Bytes[0:4],
			tenant.ID.Bytes[4:6],
			tenant.ID.Bytes[6:8],
			tenant.ID.Bytes[8:10],
			tenant.ID.Bytes[10:16])

		fmt.Printf("🏢  %-15s : %s\n", slug, uuidStr)
	}
	fmt.Println("==================================================")
	fmt.Println("⚠️  Update your Frontend .env with these IDs if they mismatch!")
}
