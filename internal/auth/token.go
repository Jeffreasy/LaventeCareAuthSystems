package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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
	GetJWKS() (*JWKS, error) // New: Export public keys
}

// Claims defines the custom JWT claims.
type Claims struct {
	UserID   uuid.UUID `json:"sub"`
	TenantID uuid.UUID `json:"tid,omitempty"`
	Role     string    `json:"role,omitempty"`
	Scope    string    `json:"scope"` // "access" or "pre_auth"
	jwt.RegisteredClaims
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWTProvider implements TokenProvider using RSA-SHA256 (RS256).
type JWTProvider struct {
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	tokenDuration time.Duration
	kid           string // Key ID for rotation support
}

// NewJWTProvider creates a new token provider.
// secretKeyPEM must be the content of the RSA PRIVATE KEY, not a filename.
func NewJWTProvider(secretKeyPEM string) *JWTProvider {
	block, _ := pem.Decode([]byte(secretKeyPEM))
	if block == nil {
		panic("failed to parse PEM block containing the private key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 if PKCS1 fails
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			panic(fmt.Sprintf("failed to parse private key: %v | %v", err, err2))
		}
		var ok bool
		priv, ok = key.(*rsa.PrivateKey)
		if !ok {
			panic("key is not of type *rsa.PrivateKey")
		}
	}

	return &JWTProvider{
		privateKey:    priv,
		publicKey:     &priv.PublicKey,
		tokenDuration: 15 * time.Minute,
		kid:           "sig-1", // Hardcoded for now, ideal for rotation later
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
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)), // Fix clock skew
			NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)), // Fix clock skew
			Issuer:    "https://laventecareauthsystems.onrender.com",
			Audience:  jwt.ClaimStrings{"convex"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.kid // Important for JWKS lookup
	signed, err := token.SignedString(p.privateKey)
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
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "https://laventecareauthsystems.onrender.com",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.kid
	signed, err := token.SignedString(p.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signed, nil
}

// ValidateToken parses and verifies the JWT.
func (p *JWTProvider) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return p.publicKey, nil
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

// GetJWKS returns the JSON Web Key Set for the public key.
func (p *JWTProvider) GetJWKS() (*JWKS, error) {
	// Convert public exponent E (int) to base64url string
	eBuf := big.NewInt(int64(p.publicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBuf)

	// Convert modulus N (big.Int) to base64url string
	n := base64.RawURLEncoding.EncodeToString(p.publicKey.N.Bytes())

	jwk := JWK{
		Kty: "RSA",
		Kid: p.kid,
		Use: "sig",
		N:   n,
		E:   e,
		Alg: "RS256",
	}

	return &JWKS{
		Keys: []JWK{jwk},
	}, nil
}
