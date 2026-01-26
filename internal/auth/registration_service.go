package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/audit"
	"github.com/Jeffreasy/LaventeCareAuthSystems/internal/storage/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// RegisterInput defines the data needed to register a new user.
type RegisterInput struct {
	Email    string
	Password string
	FullName string
	TenantID uuid.UUID
	Token    string // Invitation Token (Optional if Public Reg allowed)
}

// Register creates a new user and returns the user model.
func (s *AuthService) Register(ctx context.Context, input RegisterInput) (*db.User, error) {
	// 1. Hash Password FIRST (shared step)
	hashedPassword, err := s.passwordHasher.Hash(input.Password)
	if err != nil {
		return nil, fmt.Errorf("hashing failed: %w", err)
	}
	hashText := pgtype.Text{String: hashedPassword, Valid: true}

	// FLOW A: INVITE-BASED REGISTRATION
	if input.Token != "" {
		tokenHash := hashToken(input.Token)

		// 1. Validate Invite
		invite, err := s.queries.GetInvitationByHash(ctx, tokenHash)
		if err != nil {
			return nil, errors.New("invalid or expired invitation")
		}

		// 2. Integrity Check (Anti-Gravity Law 1: Input is toxic)
		// Ensure the registration email matches the invitation email.
		if invite.Email != input.Email {
			return nil, errors.New("email does not match invitation")
		}

		// 3. Atomically Create User + Membership + Delete Invite
		// This uses the explicit transaction query we added.
		result, err := s.queries.CreateUserFromInvitation(ctx, db.CreateUserFromInvitationParams{
			Email:        input.Email,
			PasswordHash: hashText,
			TenantID:     pgtype.UUID{Bytes: invite.TenantID.Bytes, Valid: true},
			Role:         invite.Role,
			TokenHash:    tokenHash,
		})
		if err != nil {
			return nil, fmt.Errorf("registration failed: %w", err)
		}

		// Map generic result back to DB User struct for return consistency
		// Note: The Atomic query returns partial data.
		user := &db.User{
			ID:              result.ID,
			Email:           result.Email,
			IsEmailVerified: true, // Auto-verified by invite
			CreatedAt:       result.CreatedAt,
		}

		// AUDIT LOG
		s.audit.Log(ctx, "user.create.invite", audit.LogParams{
			ActorID:  user.ID.Bytes,
			TargetID: user.ID.Bytes,
			TenantID: invite.TenantID.Bytes,
			Metadata: map[string]interface{}{
				"method":            "invite",
				"invite_token_hash": tokenHash,
			},
		})

		return user, nil
	}

	// FLOW B: PUBLIC REGISTRATION
	// 1. Check Config
	if !s.config.AllowPublicRegistration {
		return nil, ErrPublicRegistrationDisabled
	}

	// 2. Prepare DB Params
	fullNameText := pgtype.Text{String: input.FullName, Valid: input.FullName != ""}
	defaultTenantUUID := pgtype.UUID{Bytes: input.TenantID, Valid: input.TenantID != uuid.Nil}

	// 3. Create User + Membership Atomically (FIXED: was TODO service.go:175)
	// Previously: CreateUser and CreateMembership were separate → orphan users possible
	// Now: Single transaction query prevents orphan users
	// TenantID is now MANDATORY.
	user, err := s.queries.CreateUserWithMembership(ctx, db.CreateUserWithMembershipParams{
		Email:        input.Email,
		PasswordHash: hashText,
		FullName:     fullNameText,
		TenantID:     defaultTenantUUID,
		MfaSecret:    pgtype.Text{Valid: false},
		MfaEnabled:   false,
		Role:         "user", // Default Role for Public Registration
	})

	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	// AUDIT LOG
	s.audit.Log(ctx, "user.create.public", audit.LogParams{
		ActorID:  user.ID.Bytes,
		TargetID: user.ID.Bytes,
		TenantID: defaultTenantUUID.Bytes,
		Metadata: map[string]interface{}{
			"method": "public_registration",
		},
	})

	// Convert to db.User for return type compatibility
	return &db.User{
		ID:                  user.ID,
		Email:               user.Email,
		PasswordHash:        user.PasswordHash,
		FullName:            user.FullName,
		IsEmailVerified:     user.IsEmailVerified,
		TenantID:            user.TenantID,
		MfaSecret:           user.MfaSecret,
		MfaEnabled:          user.MfaEnabled,
		FailedLoginAttempts: user.FailedLoginAttempts,
		LockedUntil:         user.LockedUntil,
		CreatedAt:           user.CreatedAt,
		UpdatedAt:           user.UpdatedAt,
	}, nil
}
