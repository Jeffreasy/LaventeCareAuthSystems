package middleware

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// contextKey is a custom type for context keys to avoid collisions.
// This prevents accidental key conflicts with other packages.
type contextKey string

// Context keys for request-scoped values.
const (
	UserIDKey   contextKey = "user_id"
	TenantIDKey contextKey = "tenant_id"
	RoleKey     contextKey = "user_role"
)

// GetUserID safely extracts the user ID from context.
// Returns an error if the value is missing or wrong type.
func GetUserID(ctx context.Context) (uuid.UUID, error) {
	val := ctx.Value(UserIDKey)
	if val == nil {
		return uuid.Nil, fmt.Errorf("user_id not found in context")
	}
	id, ok := val.(uuid.UUID)
	if !ok {
		return uuid.Nil, fmt.Errorf("user_id has wrong type: %T", val)
	}
	return id, nil
}

// GetTenantID safely extracts the tenant ID from context.
// Returns an error if the value is missing or wrong type.
func GetTenantID(ctx context.Context) (uuid.UUID, error) {
	val := ctx.Value(TenantIDKey)
	if val == nil {
		return uuid.Nil, fmt.Errorf("tenant_id not found in context")
	}
	id, ok := val.(uuid.UUID)
	if !ok {
		return uuid.Nil, fmt.Errorf("tenant_id has wrong type: %T", val)
	}
	return id, nil
}

// GetRole safely extracts the user role from context.
// Returns an error if the value is missing or wrong type.
func GetRole(ctx context.Context) (string, error) {
	val := ctx.Value(RoleKey)
	if val == nil {
		return "", fmt.Errorf("user_role not found in context")
	}
	role, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("user_role has wrong type: %T", val)
	}
	return role, nil
}

// MustGetUserID extracts user ID and panics if not found.
// Use only in contexts where UserID is guaranteed to be set by middleware.
func MustGetUserID(ctx context.Context) uuid.UUID {
	id, err := GetUserID(ctx)
	if err != nil {
		panic(fmt.Sprintf("CRITICAL: %v", err))
	}
	return id
}

// MustGetTenantID extracts tenant ID and panics if not found.
// Use only in contexts where TenantID is guaranteed to be set by middleware.
func MustGetTenantID(ctx context.Context) uuid.UUID {
	id, err := GetTenantID(ctx)
	if err != nil {
		panic(fmt.Sprintf("CRITICAL: %v", err))
	}
	return id
}
