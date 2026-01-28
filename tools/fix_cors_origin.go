package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// usage: go run tools/fix_cors_origin.go <DSN>
func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run tools/fix_cors_origin.go <DSN>")
	}
	dsn := os.Args[1]

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer pool.Close()

	tenantID := "7c1efbe8-d419-4127-9ea2-a6e67ed49a1f"
	origin := "https://www.smartcoolcare.nl"

	// Check current origins
	var currentOrigins []string
	err = pool.QueryRow(ctx, "SELECT allowed_origins FROM tenants WHERE id = $1", tenantID).Scan(&currentOrigins)
	if err != nil {
		log.Fatalf("Failed to fetch tenant: %v", err)
	}
	fmt.Printf("Current Origins: %v\n", currentOrigins)

	// Update if not present
	found := false
	for _, o := range currentOrigins {
		if o == origin {
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("origin %s not found. Adding...\n", origin)
		_, err = pool.Exec(ctx, "UPDATE tenants SET allowed_origins = array_append(allowed_origins, $1) WHERE id = $2", origin, tenantID)
		if err != nil {
			log.Fatalf("Failed to update tenant: %v", err)
		}
		fmt.Println("Successfully added origin.")
	} else {
		fmt.Println("Origin already exists. No changes needed.")
	}
}
