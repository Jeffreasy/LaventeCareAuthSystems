package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Common errors
var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

// TokenProvider defines the contract for generating and validating tokens.
type TokenProvider interface {
	GenerateAccessToken(userID uuid.UUID, tenantID uuid.UUID, role string) (string, error)
	GeneratePreAuthToken(userID uuid.UUID) (string, error)
	ValidateToken(tokenString string) (*Claims, error)
}

// Claims defines the custom JWT claims.
type Claims struct {
	UserID   uuid.UUID `json:"sub"`
	TenantID uuid.UUID `json:"tid,omitempty"`
	Role     string    `json:"role,omitempty"`
	Scope    string    `json:"scope"` // "access" or "pre_auth"
	jwt.RegisteredClaims
}

// JWTProvider implements TokenProvider using HMAC-SHA256.
type JWTProvider struct {
	secretKey     []byte
	tokenDuration time.Duration
}

// NewJWTProvider creates a new token provider.
func NewJWTProvider(secretKey string) *JWTProvider {
	return &JWTProvider{
		secretKey:     []byte(secretKey),
		tokenDuration: 15 * time.Minute, // Short-lived access tokens (industry standard)
	}
}

// GenerateAccessToken creates a signed JWT for the user.
func (p *JWTProvider) GenerateAccessToken(userID uuid.UUID, tenantID uuid.UUID, role string) (string, error) {
	claims := Claims{
		UserID:   userID,
		TenantID: tenantID,
		Role:     role,
		Scope:    "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(p.tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "laventecare-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(p.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signed, nil
}

// GeneratePreAuthToken creates a short-lived token for MFA verification step.
func (p *JWTProvider) GeneratePreAuthToken(userID uuid.UUID) (string, error) {
	claims := Claims{
		UserID: userID,
		Scope:  "pre_auth",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Minute)), // Strict 2m window
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "laventecare-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(p.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signed, nil
}

// ValidateToken parses and verifies the JWT.
func (p *JWTProvider) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return p.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}
