//go:build ignore

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
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

	ctx := context.Background()

	// 1. Create Tenant
	tenantID := uuid.New()
	tenantSlug := "smartcoolcare"
	tenantName := "SmartCoolCare"

	secretKeyPlaceholder := "placeholder_will_be_set_by_auth_service"
	secretHash, _ := bcrypt.GenerateFromPassword([]byte(secretKeyPlaceholder), bcrypt.DefaultCost)

	_, err = pool.Exec(ctx, `
		INSERT INTO tenants (id, name, slug, secret_key_hash, allowed_origins, redirect_urls, is_active, app_url)
		VALUES ($1, $2, $3, $4, $5, $6, true, $7)
	`, tenantID, tenantName, tenantSlug, string(secretHash),
		[]string{"https://laventecareauthsystems.onrender.com"},
		[]string{"https://laventecareauthsystems.onrender.com/auth/callback"},
		"https://laventecareauthsystems.onrender.com")

	if err != nil {
		fmt.Printf("Failed to create tenant: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Tenant created: %s (ID: %s)\n", tenantName, tenantID)

	// 2. Create User
	userID := uuid.New()
	email := "jeffrey@smartcoolcare.nl"
	password := "Oprotten@12"
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	_, err = pool.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, full_name, is_email_verified, default_tenant_id)
		VALUES ($1, $2, $3, $4, true, $5)
	`, userID, email, string(passwordHash), "Jeffrey", tenantID)

	if err != nil {
		fmt.Printf("Failed to create user: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ User created: %s\n", email)

	// 3. Create Membership
	membershipID := uuid.New()
	_, err = pool.Exec(ctx, `
		INSERT INTO memberships (id, user_id, tenant_id, role)
		VALUES ($1, $2, $3, 'admin')
	`, membershipID, userID, tenantID)

	if err != nil {
		fmt.Printf("Failed to create membership: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Admin membership created")

	// 4. Register IoT Devices
	devices := []struct {
		DeviceID   string
		SecretHash string
		Name       string
	}{
		{"Koelkast_A", "$2a$10$zm23aPeSYMRBh3LS4ETerezBKQ5LgyqO3M01t9.za7xPrnYp0HbjG", "Koelkast A"},
		{"Koelkast_B", "$2a$10$pZcLEokxyOZypshdsJMnXOX7k7N/jrUauGLWYP/zr2naKZPNWLz9y", "Koelkast B"},
		{"Koelkast_C", "$2a$10$tfhbUlwCFXRVPf4YoaiSSOzKPESu6/ebxRMOjTVnJkTvbre6Rkrii", "Koelkast C"},
		{"Koelkast_D", "$2a$10$TeFMoMf6xr7Pd464BN1LQOsM3BEDNKTAmlfZKI.yIsFXVMwQiHaPu", "Koelkast D"},
	}

	for _, device := range devices {
		deviceUUID := uuid.New()
		_, err = pool.Exec(ctx, `
			INSERT INTO iot_devices (id, device_id, tenant_id, secret_hash, name, is_active)
			VALUES ($1, $2, $3, $4, $5, true)
		`, deviceUUID, device.DeviceID, tenantID, device.SecretHash, device.Name)

		if err != nil {
			fmt.Printf("❌ Failed to register %s: %v\n", device.DeviceID, err)
		} else {
			fmt.Printf("✅ Device registered: %s\n", device.Name)
		}
	}

	fmt.Println("\n=== SETUP COMPLETE ===")
	fmt.Printf("Tenant: %s (%s)\n", tenantName, tenantID)
	fmt.Printf("Email:  %s\n", email)
	fmt.Println("Password: [provided]")
	fmt.Println("\nYou can now:")
	fmt.Println("1. Login to the auth system")
	fmt.Println("2. Flash your ESP32 devices with their secrets")
	fmt.Println("3. Start receiving telemetry data!")
}
