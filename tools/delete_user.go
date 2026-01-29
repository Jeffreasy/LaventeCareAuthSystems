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
		log.Println("Note: .env.local not found, trying .env")
		if err := godotenv.Load(); err != nil {
			log.Printf("Warning: No .env file found: %v", err)
		}
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

	email := "laventejeffrey@gmail.com"
	if len(os.Args) > 1 {
		email = os.Args[1]
	}

	fmt.Printf("Attempting to delete user: %s\n", email)

	// 3. Delete User (and cascade dependencies if configured, otherwise we might need multiple deletes)
	// We'll try a transaction to be safe.
	tx, err := conn.Begin(ctx)
	if err != nil {
		log.Fatalf("Failed to begin transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	// Delete from memberships first (foreign key likely)
	// Assuming 'memberships' table exists and links to users.id
	// If we don't know the schema perfectly, we can try deleting from users and see if it fails.
	// The previous error was a 500 on register, likely a Unique constraint on users.email.

	// Let's try to find the user first
	var userID string
	err = tx.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	if err == pgx.ErrNoRows {
		fmt.Println("User not found in database. Nothing to delete.")
		return
	} else if err != nil {
		log.Fatalf("Error finding user: %v", err)
	}

	fmt.Printf("Found User ID: %s\n", userID)

	// Verify tables for cleanup (audit_logs, memberships, etc) might reference it.
	// We will attempt a CASCADE delete if the Schema supports it, or manual deletes.
	// Usually 'users' is the root. Let's try deleting it.
	// If there are ON DELETE CASCADE constraints, it will work.
	// If NOT, we might get an error.

	cmdTag, err := tx.Exec(ctx, "DELETE FROM users WHERE email = $1", email)
	if err != nil {
		// If it fails, likely constraint violation.
		fmt.Printf("Delete failed: %v. Attempting to clean dependencies first...\n", err)

		// Clean Memberships
		_, err = tx.Exec(ctx, "DELETE FROM memberships WHERE user_id = $1", userID)
		if err != nil {
			log.Printf("Failed to delete memberships: %v", err)
		}

		// Clean Refresh Tokens
		_, err = tx.Exec(ctx, "DELETE FROM refresh_tokens WHERE user_id = $1", userID)
		if err != nil {
			log.Printf("Failed to delete refresh_tokens: %v", err)
		}

		// Retry User Delete
		cmdTag, err = tx.Exec(ctx, "DELETE FROM users WHERE email = $1", email)
		if err != nil {
			log.Fatalf("Failed to delete user after cleanup: %v", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		log.Fatalf("Failed to commit transaction: %v", err)
	}

	if cmdTag.RowsAffected() == 0 {
		fmt.Println("No user found/deleted (unexpected after check).")
	} else {
		fmt.Printf("Successfully deleted user: %s (Rows affected: %d)\n", email, cmdTag.RowsAffected())
	}
}
