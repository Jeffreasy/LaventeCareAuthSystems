// Package crypto provides encryption/decryption utilities for sensitive tenant data.
// Uses AES-256-GCM for authenticated encryption with key versioning support.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// EncryptTenantSecret encrypts a tenant SMTP password using AES-256-GCM.
// The master key is loaded from env var TENANT_SECRET_KEY (32 bytes = 64 hex chars).
//
// Security Notes:
// - Uses GCM (Galois/Counter Mode) for authenticated encryption
// - Generates random nonce per encryption (CRITICAL for security)
// - Returns base64-encoded ciphertext prefixed with "enc:" for storage
// - Master key MUST be rotated periodically (see key versioning)
//
// Anti-Gravity Law 1: Input is Toxic - validates key format before use
// Anti-Gravity Law 5: Dependency Paranoia - uses only stdlib crypto
func EncryptTenantSecret(plaintext string) (string, error) {
	// 1. Load and validate master key from environment
	keyHex := os.Getenv("TENANT_SECRET_KEY")
	if len(keyHex) != 64 {
		return "", fmt.Errorf("TENANT_SECRET_KEY must be exactly 32 bytes (64 hex characters)")
	}

	key := make([]byte, 32)
	n, err := hex.Decode(key, []byte(keyHex))
	if err != nil {
		return "", fmt.Errorf("invalid TENANT_SECRET_KEY format (must be hex): %w", err)
	}
	if n != 32 {
		return "", fmt.Errorf("TENANT_SECRET_KEY decoded to %d bytes, expected 32", n)
	}

	// 2. Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// 3. Generate cryptographically secure random nonce
	// CRITICAL: Nonce MUST be unique for each encryption with the same key
	// Reusing a nonce completely breaks GCM security
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 4. Encrypt (nonce is prepended to ciphertext for later decryption)
	// GCM provides both confidentiality AND authenticity (AEAD)
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// 5. Base64 encode for safe JSON storage, prefix with "enc:" for identification
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return "enc:" + encoded, nil
}

// DecryptTenantSecret decrypts an AES-256-GCM encrypted password.
//
// Security Notes:
// - Validates "enc:" prefix to prevent processing plaintext
// - Returns error on tampering (GCM authentication failure)
// - NEVER logs the decrypted password (Law 2: Silence is Golden)
//
// The decrypted password should ONLY exist in memory during SMTP connection,
// and should NEVER be written to logs, Sentry, or database.
func DecryptTenantSecret(ciphertextB64 string) (string, error) {
	// 1. Validate format (must start with "enc:")
	if len(ciphertextB64) < 4 || ciphertextB64[:4] != "enc:" {
		return "", fmt.Errorf("invalid encrypted format (missing 'enc:' prefix)")
	}

	// 2. Load master key
	keyHex := os.Getenv("TENANT_SECRET_KEY")
	if len(keyHex) != 64 {
		return "", fmt.Errorf("TENANT_SECRET_KEY not configured or invalid length")
	}

	key := make([]byte, 32)
	if _, err := hex.Decode(key, []byte(keyHex)); err != nil {
		return "", fmt.Errorf("invalid TENANT_SECRET_KEY: %w", err)
	}

	// 3. Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64[4:]) // Skip "enc:" prefix
	if err != nil {
		return "", fmt.Errorf("invalid base64 encoding: %w", err)
	}

	// 4. Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// 5. Extract nonce and decrypt
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short (possible corruption or tampering)")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// GCM.Open validates authenticity before decrypting
	// Returns error if data has been tampered with
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (invalid key or tampered data): %w", err)
	}

	return string(plaintext), nil
}

// DecryptTenantSecretV decrypts using versioned keys (for key rotation).
//
// Key Rotation Workflow:
// 1. Generate new key: openssl rand -hex 32
// 2. Add to env: TENANT_SECRET_KEY_V2=<new-key>
// 3. Deploy code with both V1 and V2 support
// 4. Background job re-encrypts all configs with V2
// 5. Update mail_config_key_version = 2 in database
// 6. Remove TENANT_SECRET_KEY (V1) after all data migrated
func DecryptTenantSecretV(ciphertextB64 string, keyVersion int) (string, error) {
	var keyEnvVar string

	switch keyVersion {
	case 1:
		keyEnvVar = "TENANT_SECRET_KEY"
	case 2:
		keyEnvVar = "TENANT_SECRET_KEY_V2"
	case 3:
		keyEnvVar = "TENANT_SECRET_KEY_V3"
	default:
		return "", fmt.Errorf("unsupported key version: %d (max supported: 3)", keyVersion)
	}

	// Load versioned key
	keyHex := os.Getenv(keyEnvVar)
	if keyHex == "" {
		return "", fmt.Errorf("encryption key version %d not found in environment (%s)", keyVersion, keyEnvVar)
	}

	// Temporarily override TENANT_SECRET_KEY for DecryptTenantSecret
	// (In production, refactor to pass key directly to avoid env manipulation)
	oldKey := os.Getenv("TENANT_SECRET_KEY")
	os.Setenv("TENANT_SECRET_KEY", keyHex)
	defer os.Setenv("TENANT_SECRET_KEY", oldKey)

	return DecryptTenantSecret(ciphertextB64)
}

// GenerateKey generates a new 32-byte AES encryption key in hex format.
// Usage: Run this during initial setup or key rotation.
//
// Example:
//
//	key, _ := crypto.GenerateKey()
//	fmt.Println("Add to Render secrets:")
//	fmt.Println("TENANT_SECRET_KEY=" + key)
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}
	return hex.EncodeToString(key), nil
}
