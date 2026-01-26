package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/auth"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/config"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/domain"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
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
	case "rotate-secret":
		rotateSecretCmd()
	case "check-user":
		checkUserCmd()
	case "fix-membership":
		fixMembershipCmd()
	case "reset-password":
		resetPasswordCmd()
	default:
		log.Fatalf("Unknown command: %s", cmd)
	}
}

func resetPasswordCmd() {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	email := fs.String("email", "", "User Email")
	password := fs.String("password", "", "New Password")
	tenant := fs.String("tenant", "", "Tenant ID (UUID)")
	fs.Parse(os.Args[2:])

	if *email == "" || *password == "" || *tenant == "" {
		fmt.Println("Error: --email, --password, and --tenant are required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	tenantUUID, err := uuid.Parse(*tenant)
	if err != nil {
		log.Fatalf("Invalid tenant ID: %v", err)
	}

	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	pool, err := storage.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	// queries := storage.New(pool) // Not used for direct update if we do manual query, but let's see.

	// 1. Hash Password
	hasher := auth.NewBcryptHasher()
	hash, err := hasher.Hash(*password)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	// 2. Update DB
	// Using Exec for direct update
	cmdTag, err := pool.Exec(context.Background(),
		"UPDATE users SET password_hash = $1, updated_at = NOW() WHERE email = $2 AND tenant_id = $3",
		hash, *email, tenantUUID)

	if err != nil {
		log.Fatalf("❌ Failed to update password: %v", err)
	}

	if cmdTag.RowsAffected() == 0 {
		log.Fatalf("❌ User found found with email: %s", *email)
	}

	fmt.Printf("✅ Password Reset Successfully for %s\n", *email)
}

func fixMembershipCmd() {
	fs := flag.NewFlagSet("fix-membership", flag.ExitOnError)
	email := fs.String("email", "", "User Email")
	tenant := fs.String("tenant", "", "Tenant ID (UUID)")
	fs.Parse(os.Args[2:])

	if *email == "" || *tenant == "" {
		fmt.Println("Error: --email and --tenant are required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	pool, err := storage.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	queries := storage.New(pool)

	tenantUUID, err := uuid.Parse(*tenant)
	if err != nil {
		log.Fatalf("Invalid tenant ID: %v", err)
	}

	// Fetch User
	user, err := queries.GetUserByEmail(context.Background(), db.GetUserByEmailParams{
		Email:    *email,
		TenantID: pgtype.UUID{Bytes: tenantUUID, Valid: true},
	})
	if err != nil {
		log.Fatalf("❌ User not found: %v", err)
	}

	if !user.TenantID.Valid {
		log.Fatalf("❌ User has no tenant (this should not happen with strict isolation).")
	}

	// Create Membership
	// Direct SQL execution since we don't know if specific CreateMembership query fits our need perfectly or we want to be explicit
	// Actually we should use queries.CreateMembership if available.
	// But let's check what exists. I'll use Exec for simplicity and speed.

	cmdTag, err := pool.Exec(context.Background(),
		"INSERT INTO memberships (user_id, tenant_id, role) VALUES ($1, $2, 'admin') ON CONFLICT DO NOTHING",
		user.ID.Bytes, user.TenantID.Bytes)

	if err != nil {
		log.Fatalf("❌ CONFIG FAILED: %v", err)
	}

	if cmdTag.RowsAffected() == 0 {
		fmt.Println("⚠️  Membership already exists (or conflict ignored).")
	} else {
		fmt.Printf("✅ Membership FIXED! User %s is now admin of their default tenant.\n", *email)
	}
}

func checkUserCmd() {
	fs := flag.NewFlagSet("check-user", flag.ExitOnError)
	email := fs.String("email", "", "User Email")
	tenant := fs.String("tenant", "", "Tenant ID (UUID)")
	fs.Parse(os.Args[2:])

	if *email == "" || *tenant == "" {
		fmt.Println("Error: --email and --tenant are required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	pool, err := storage.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	queries := storage.New(pool)

	tenantUUID, err := uuid.Parse(*tenant)
	if err != nil {
		log.Fatalf("Invalid tenant ID: %v", err)
	}

	// Fetch User
	user, err := queries.GetUserByEmail(context.Background(), db.GetUserByEmailParams{
		Email:    *email,
		TenantID: pgtype.UUID{Bytes: tenantUUID, Valid: true},
	})
	if err != nil {
		log.Fatalf("❌ User not found: %v", err)
	}

	fmt.Printf("✅ User Found\n")
	fmt.Printf("ID: %x\n", user.ID.Bytes)
	fmt.Printf("Email: %s\n", user.Email)

	if user.TenantID.Valid {
		uid, _ := uuid.FromBytes(user.TenantID.Bytes[:])
		fmt.Printf("\n>>> TENANT_ID: %s <<<\n", uid.String())

		// Verify if tenant exists
		t, err := queries.GetTenantByID(context.Background(), pgtype.UUID{Bytes: user.TenantID.Bytes, Valid: true})
		if err != nil {
			fmt.Printf("⚠️  WARNING: Default Tenant ID points to NON-EXISTENT tenant! (%v)\n", err)
		} else {
			fmt.Printf("   -> Tenant Name: %s\n", t.Name)

			// Check Membership
			m, err := queries.GetMembership(context.Background(), db.GetMembershipParams{
				UserID:   pgtype.UUID{Bytes: user.ID.Bytes, Valid: true},
				TenantID: pgtype.UUID{Bytes: t.ID.Bytes, Valid: true},
			})
			if err != nil {
				fmt.Printf("❌ CRITICAL: User has Default Tenant but NO MEMBERSHIP! (%v)\n", err)
			} else {
				fmt.Printf("✅ Membership Found. Role: %s\n", m)
			}
		}
	} else {
		fmt.Printf("Default Tenant ID: NULL\n")
	}
}

func rotateSecretCmd() {
	fs := flag.NewFlagSet("rotate-secret", flag.ExitOnError)
	slug := fs.String("slug", "", "Tenant Slug (e.g. 'de-koninklijkeloop')")

	fs.Parse(os.Args[2:])

	if *slug == "" {
		fmt.Println("Error: --slug is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	pool, err := storage.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	// Direct DB execution for update since we don't have a generated query for this specific partial update yet
	// Or we can use custom SQL.

	// 1. Generate Secret Key
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate random bytes: %v", err)
	}
	rawSecretKey := hex.EncodeToString(bytes)

	// 2. Hash Secret Key
	hasher := auth.NewBcryptHasher()
	secretKeyHash, err := hasher.Hash(rawSecretKey)
	if err != nil {
		log.Fatalf("Failed to hash secret key: %v", err)
	}

	// 3. Update DB
	// We use Exec directly because we don't have a specific sqlc query for receiving just the slug and updating secret
	// And I don't want to regenerate sqlc right now.
	_, err = pool.Exec(context.Background(),
		"UPDATE tenants SET secret_key_hash = $1, updated_at = NOW() WHERE slug = $2",
		secretKeyHash, *slug)

	if err != nil {
		log.Fatalf("❌ Failed to update tenant: %v", err)
	}

	fmt.Printf("✅ Tenant Secret Rotated Successfully!\n")
	fmt.Printf("----------------------------------------------------------------\n")
	fmt.Printf("Tenant Slug: %s\n", *slug)
	fmt.Printf("----------------------------------------------------------------\n")
	fmt.Printf("⚠️  NEW SECRET KEY (SAVE THIS NOW) ⚠️\n")
	fmt.Printf("Secret Key: %s\n", rawSecretKey)
	fmt.Printf("----------------------------------------------------------------\n")
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

	// 3. Generate Secret Key
	// Generate 32 bytes of random data (256 bits)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate random bytes: %v", err)
	}
	rawSecretKey := hex.EncodeToString(bytes)

	// 4. Hash Secret Key
	hasher := auth.NewBcryptHasher()
	secretKeyHash, err := hasher.Hash(rawSecretKey)
	if err != nil {
		log.Fatalf("Failed to hash secret key: %v", err)
	}

	// 5. Create Tenant
	t, err := queries.CreateTenant(context.Background(), db.CreateTenantParams{
		Name:           *name,
		Slug:           *slug,
		AppUrl:         *url,
		AllowedOrigins: []string{*url}, // Default allow self
		RedirectUrls:   []string{*url + "/auth/callback"},
		Branding:       domain.TenantBranding{},
		Settings:       domain.TenantSettings{},
		SecretKeyHash:  secretKeyHash,
	})

	if err != nil {
		log.Fatalf("❌ Failed to create tenant: %v", err)
	}

	fmt.Printf("✅ Tenant Created Successfully!\n")
	fmt.Printf("----------------------------------------------------------------\n")
	fmt.Printf("ID:         %s\n", t.ID)
	fmt.Printf("Name:       %s\n", t.Name)
	fmt.Printf("Slug:       %s\n", t.Slug)
	fmt.Printf("URL:        %s\n", t.AppUrl)
	fmt.Printf("Public Key: %s\n", t.PublicKey)
	fmt.Printf("----------------------------------------------------------------\n")
	fmt.Printf("⚠️  SECRET KEY (SAVE THIS NOW, IT WILL NOT BE SHOWN AGAIN) ⚠️\n")
	fmt.Printf("Secret Key: %s\n", rawSecretKey)
	fmt.Printf("----------------------------------------------------------------\n")
}
