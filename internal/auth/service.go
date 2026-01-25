package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/audit"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/notify"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUserNotFound               = errors.New("user not found")
	ErrInvalidCredentials         = errors.New("invalid email or password")
	ErrTenantRequired             = errors.New("tenant id is required")
	ErrPublicRegistrationDisabled = errors.New("public registration is disabled")
)

// AuthConfig holds configuration for the auth service.
type AuthConfig struct {
	AllowPublicRegistration bool
	DefaultAppURL           string // Fallback URL for email links when tenant has no custom app_url
}

// AuthService orchestrates the authentication flow.
// It is agnostic of HTTP transport (Chi) or Database implementation (pgx).
type AuthService struct {
	config         AuthConfig
	pool           *pgxpool.Pool // Added for RLS Transactions
	queries        *db.Queries
	passwordHasher PasswordHasher
	tokenProvider  TokenProvider
	mfaService     *MFAService
	audit          audit.AuditService // NEW
	mail           notify.EmailSender
}

func NewAuthService(
	config AuthConfig,
	pool *pgxpool.Pool,
	queries *db.Queries,
	hasher PasswordHasher,
	tokenProvider TokenProvider,
	mfa *MFAService,
	audit audit.AuditService, // NEW
	mail notify.EmailSender,
) *AuthService {
	return &AuthService{
		config:         config,
		pool:           pool,
		queries:        queries,
		passwordHasher: hasher,
		tokenProvider:  tokenProvider,
		mfaService:     mfa,
		audit:          audit,
		mail:           mail,
	}
}

// resolveTenantAndRole resolves the tenant ID and role for a user.
// This helper reduces code duplication across Login, MFA verification and token refresh flows.
// Returns (tenantID, role, error). If user has no default tenant, returns (uuid.Nil, "", nil).
func (s *AuthService) resolveTenantAndRole(ctx context.Context, user db.User) (uuid.UUID, string, error) {
	tenantID := uuid.Nil
	role := ""

	if !user.DefaultTenantID.Valid {
		return tenantID, role, nil
	}

	tenantID = uuid.UUID(user.DefaultTenantID.Bytes)

	// Fetch role for this tenant
	membership, err := s.queries.GetMembership(ctx, db.GetMembershipParams{
		UserID:   pgtype.UUID{Bytes: user.ID.Bytes, Valid: true},
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
	})
	if err != nil {
		// User has default_tenant_id but no membership? Return Nil tenant (degraded)
		return uuid.Nil, "", nil
	}

	role = membership // GetMembership returns string (role column)
	return tenantID, role, nil
}

// WithRLS executes a function within a transaction that has the RLS context set.
func (s *AuthService) WithRLS(ctx context.Context, tenantID uuid.UUID, fn func(q *db.Queries) error) error {
	// 1. Begin Transaction
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// 2. Set RLS Context Variable (Postgres Session Local)
	// We use set_config with 'is_local' = true, so it applies only to this transaction.
	_, err = tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set rls context: %w", err)
	}

	// 3. Execute Logic with Tx-wrapped Queries
	q := s.queries.WithTx(tx)
	if err := fn(q); err != nil {
		return err
	}

	// 4. Commit
	return tx.Commit(ctx)
}

// GetJWKS returns the JSON Web Key Set for the OIDC provider.
func (s *AuthService) GetJWKS() (*JWKS, error) {
	return s.tokenProvider.GetJWKS()
}
