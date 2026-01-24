package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/config"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/domain"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: control <command> [args]")
		fmt.Println("Commands:")
		fmt.Println("  create-tenant  Create a new tenant")
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "create-tenant":
		createTenantCmd()
	default:
		log.Fatalf("Unknown command: %s", cmd)
	}
}

func createTenantCmd() {
	fs := flag.NewFlagSet("create-tenant", flag.ExitOnError)
	name := fs.String("name", "", "Tenant Name (e.g. 'Bakkerij Jansen')")
	slug := fs.String("slug", "", "URL Slug (e.g. 'bakkerij-jansen')")
	url := fs.String("url", "", "App URL (e.g. 'https://bakkerij.nl')")

	// Parse starting from 2nd arg
	fs.Parse(os.Args[2:])

	if *name == "" || *slug == "" || *url == "" {
		fmt.Println("Error: --name, --slug, and --url are required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// 1. Load Config
	cfg := config.Load()

	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	// 2. Connect DB
	pool, err := storage.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	queries := storage.New(pool)

	// 3. Create Tenant
	t, err := queries.CreateTenant(context.Background(), db.CreateTenantParams{
		Name:           *name,
		Slug:           *slug,
		AppUrl:         *url,
		AllowedOrigins: []string{*url}, // Default allow self
		RedirectUrls:   []string{*url + "/auth/callback"},
		Branding:       domain.TenantBranding{},
		Settings:       domain.TenantSettings{},
		SecretKeyHash:  "cli-generated-hash-placeholder", // Function provided by Auth service, not available here without import.
	})

	if err != nil {
		log.Fatalf("❌ Failed to create tenant: %v", err)
	}

	fmt.Printf("✅ Tenant Created Successfully!\n")
	fmt.Printf("ID:   %s\n", t.ID)
	fmt.Printf("Name: %s\n", t.Name)
	fmt.Printf("Slug: %s\n", t.Slug)
	fmt.Printf("URL:  %s\n", t.AppUrl)
}
