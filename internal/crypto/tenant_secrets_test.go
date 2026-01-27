package crypto

import (
	"testing"
)

func TestEncryptDecryptTenantSecret(t *testing.T) {
	// Set up test key (32 bytes = 64 hex chars)
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv("TENANT_SECRET_KEY", testKey)

	plaintext := "MySuperSecretPassword123!"

	// Encrypt
	encrypted, err := EncryptTenantSecret(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify format
	if len(encrypted) < 5 || encrypted[:4] != "enc:" {
		t.Errorf("Encrypted output missing 'enc:' prefix: %s", encrypted)
	}

	// Decrypt
	decrypted, err := DecryptTenantSecret(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify roundtrip
	if decrypted != plaintext {
		t.Errorf("Decrypted text doesn't match original.\nGot: %s\nWant: %s", decrypted, plaintext)
	}
}

func TestDecryptTenantSecret_InvalidFormat(t *testing.T) {
	t.Setenv("TENANT_SECRET_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	// Try to decrypt plaintext (no "enc:" prefix)
	_, err := DecryptTenantSecret("plaintext password")
	if err == nil {
		t.Error("Expected error for plaintext input, got nil")
	}
}

func TestDecryptTenantSecret_TamperedData(t *testing.T) {
	testKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv("TENANT_SECRET_KEY", testKey)

	encrypted, _ := EncryptTenantSecret("test")

	// Tamper with the ciphertext
	tampered := encrypted[:len(encrypted)-5] + "XXXXX"

	_, err := DecryptTenantSecret(tampered)
	if err == nil {
		t.Error("Expected error for tampered ciphertext, got nil")
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Verify length (32 bytes = 64 hex characters)
	if len(key) != 64 {
		t.Errorf("Generated key has wrong length. Got %d, want 64", len(key))
	}

	// Verify it's valid hex
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Generated key contains non-hex character: %c", c)
			break
		}
	}
}

func TestDecryptTenantSecretV_Version2(t *testing.T) {
	keyV1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	keyV2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	t.Setenv("TENANT_SECRET_KEY", keyV1)
	t.Setenv("TENANT_SECRET_KEY_V2", keyV2)

	// Encrypt with V2 key
	plaintext := "PasswordWithV2Key"
	_, _ = EncryptTenantSecret(plaintext) // V1 (unused)

	// Temporarily switch to V2 for encryption
	t.Setenv("TENANT_SECRET_KEY", keyV2)
	encryptedV2, _ := EncryptTenantSecret(plaintext)
	t.Setenv("TENANT_SECRET_KEY", keyV1) // Restore

	// Decrypt using versioned function
	decrypted, err := DecryptTenantSecretV(encryptedV2, 2)
	if err != nil {
		t.Fatalf("Decryption with V2 key failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text mismatch. Got: %s, Want: %s", decrypted, plaintext)
	}
}
