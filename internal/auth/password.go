package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHasher defines the contract for password operations.
// This interface allows us to easily mock hashing in tests or swap algorithms.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
}

// BcryptHasher implements PasswordHasher using the bcrypt algorithm.
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher creates a new hasher with the default cost (12).
// You can increase this cost as hardware gets faster.
func NewBcryptHasher() *BcryptHasher {
	return &BcryptHasher{
		cost: 12, // Increased to 12 as per Anti-Gravity Active Defense standards
	}
}

// Hash returns the bcrypt hash of the password.
func (h *BcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(bytes), nil
}

// Compare checks if the provided password matches the hash.
// Returns nil if match, error otherwise.
func (h *BcryptHasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
