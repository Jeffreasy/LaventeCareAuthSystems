package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/domain"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// Config
var (
	password      = "Oprotten@12"
	tenantsConfig = []struct {
		Name   string
		Slug   string
		Email  string
		AppURL string
	}{
		{
			Name:   "De Koninklijke Loop",
			Slug:   "dkl",
			Email:  "jeffrey@dekoninklijkeloop.nl",
			AppURL: "https://dekoninklijkeloop.nl",
		},
		{
			Name:   "LaventeCare",
			Slug:   "laventecare",
			Email:  "jeffrey@laventecare.nl",
			AppURL: "https://laventecare.nl",
		},
	}
)

func main() {
	// 1. Load Env
	// Try loading .env.local first (Render Dev), then .env
	if err := godotenv.Load(".env.local"); err != nil {
		if err := godotenv.Load(); err != nil {
			log.Println("Warning: No .env or .env.local found, using system env")
		}
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	// 2. Connect DB
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer pool.Close()

	queries := db.New(pool)
	log.Println("✅ Connected to Database")

	// 3. Hash Password (Once, reused)
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(hashedBytes)

	// 4. Iterate and Create
	for _, t := range tenantsConfig {
		log.Printf("🚀 Provisioning: %s (%s)...", t.Name, t.Slug)

		// A. Check if exists
		existing, err := queries.GetTenantBySlug(ctx, t.Slug)
		if err == nil {
			log.Printf("   ⚠️ Tenant '%s' already exists (ID: %s). Skipping creation.", t.Slug, existing.ID.Bytes)
			// Optional: Ensure user exists for existing tenant?
			// For now, skip to minimize side effects on existing data.
			continue
		}

		// B. Create Tenant
		// Fake a secret key hash for now (in production, use crypto.GenerateKey)
		secretHash, _ := bcrypt.GenerateFromPassword([]byte("tenant-secret-"+t.Slug), 10)

		tenant, err := queries.CreateTenant(ctx, db.CreateTenantParams{
			Name:          t.Name,
			Slug:          t.Slug,
			SecretKeyHash: string(secretHash),
			AllowedOrigins: []string{
				"http://localhost:3000",
				"http://localhost:4321",
				t.AppURL,
			},
			RedirectUrls: []string{},
			Branding: domain.TenantBranding{
				PrimaryColor: "#ff6b00", // Default Orange
			},
			Settings: domain.TenantSettings{
				AllowRegistration: false,
			},
			AppUrl: t.AppURL,
		})
		if err != nil {
			log.Printf("   ❌ Failed to create tenant: %v", err)
			continue
		}
		log.Printf("   ✅ Tenant Created: %s", tenant.ID.Bytes)

		// C. Create User & Membership
		// We use atomic CreateUserWithMembership if possible, or manual transaction.
		// Since we are in a script, we can just call the procedure if it exists or do it manually.
		// let's use CreateUserWithMembership as it's cleaner.

		user, err := queries.CreateUserWithMembership(ctx, db.CreateUserWithMembershipParams{
			Email:        t.Email,
			PasswordHash: pgtype.Text{String: passwordHash, Valid: true},
			FullName:     pgtype.Text{String: "Jeffrey Lavente", Valid: true},
			TenantID:     tenant.ID,
			MfaSecret:    pgtype.Text{Valid: false},
			MfaEnabled:   false,
			Role:         "admin", // SUPER ADMIN for this tenant
		})
		if err != nil {
			log.Printf("   ❌ Failed to create user %s: %v", t.Email, err)
			continue
		}
		log.Printf("   ✅ Admin User Created: %s (Role: admin)", t.Email)

		// D. AUDIT LOG (Compliance)
		// We must manually insert the audit log since we bypassed the Service Layer
		metadata := fmt.Sprintf(`{"method":"bootstrap_script", "slug":"%s", "admin_email":"%s"}`, t.Slug, t.Email)

		err = queries.CreateAuditLog(ctx, db.CreateAuditLogParams{
			ActorID: user.ID, // The user themselves "created" it effectively, or system.
			// Actually, system created it. But let's attribute to the new user for traceability if they log inside.
			// Or better: Use uuid.Nil for System?
			// Let's use the User ID so they see it in their log.
			SessionID: pgtype.UUID{Valid: false},
			TenantID:  tenant.ID,
			Action:    "tenant.bootstrap",
			TargetID:  tenant.ID,
			Metadata:  []byte(metadata),
		})
		if err != nil {
			log.Printf("   ⚠️ Failed to write audit log: %v", err)
		} else {
			log.Printf("   ✅ Audit Log Written")
		}
	}

	log.Println("🏁 Bootstrap Complete.")
}
