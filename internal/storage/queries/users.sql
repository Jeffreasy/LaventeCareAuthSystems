-- name: CreateUser :one
INSERT INTO users (
    email, password_hash, full_name, default_tenant_id, mfa_secret, mfa_enabled
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1 LIMIT 1;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1 LIMIT 1;

-- name: UpdateUserPassword :one
UPDATE users
SET password_hash = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: VerifyUserEmail :one
UPDATE users
SET is_email_verified = TRUE, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateUserMFA :one
UPDATE users
SET mfa_secret = $2, mfa_enabled = $3, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: IncrementLoginAttempts :exec
UPDATE users
SET failed_login_attempts = failed_login_attempts + 1, updated_at = NOW()
WHERE id = $1;

-- name: ResetLoginAttempts :exec
UPDATE users
SET failed_login_attempts = 0, locked_until = NULL, updated_at = NOW()
WHERE id = $1;

-- name: LockUserAccount :exec
UPDATE users
SET locked_until = $2, failed_login_attempts = 0, updated_at = NOW()
WHERE id = $1;

-- name: CreateUserFromInvitation :one
WITH new_user AS (
    INSERT INTO users (email, password_hash, is_email_verified)
    VALUES (sqlc.arg(email), sqlc.arg(password_hash), TRUE) -- Verified because they got the invite email
    RETURNING id, email, created_at
),
new_membership AS (
    INSERT INTO memberships (user_id, tenant_id, role)
    SELECT id, sqlc.arg(tenant_id), sqlc.arg(role)
    FROM new_user
    RETURNING user_id
),
deleted_invite AS (
    DELETE FROM invitations 
    WHERE token_hash = sqlc.arg(token_hash)
)
SELECT id, email, created_at FROM new_user;

-- name: GetUserContext :one
SELECT 
    u.id, 
    u.email, 
    u.full_name,
    m.role,
    t.id as tenant_id,
    t.slug as tenant_slug
FROM users u
JOIN memberships m ON u.id = m.user_id
JOIN tenants t ON m.tenant_id = t.id
WHERE u.id = $1 AND t.id = $2;

-- name: UpdateUserProfile :exec
UPDATE users
SET 
    full_name = COALESCE($1, full_name),
    updated_at = NOW()
WHERE id = $2;

-- name: CreateUserWithMembership :one
-- Atomically creates a user and their default tenant membership
-- Prevents orphan users if membership creation fails (resolves TODO service.go:175)
-- Note: Membership is only created if tenant_id_for_membership is NOT NULL
WITH new_user AS (
    INSERT INTO users (email, password_hash, full_name, default_tenant_id, mfa_secret, mfa_enabled)
    VALUES (
        sqlc.arg(email),
        sqlc.arg(password_hash),
        sqlc.arg(full_name),
        sqlc.arg(default_tenant_id),
        sqlc.arg(mfa_secret),
        sqlc.arg(mfa_enabled)
    )
    RETURNING id, email, password_hash, full_name, is_email_verified, default_tenant_id, created_at, updated_at, mfa_secret, mfa_enabled, failed_login_attempts, locked_until
),
new_membership AS (
    INSERT INTO memberships (user_id, tenant_id, role)
    SELECT new_user.id, sqlc.narg(tenant_id_for_membership)::uuid, sqlc.arg(role)
    FROM new_user
    WHERE sqlc.narg(tenant_id_for_membership) IS NOT NULL
    RETURNING user_id
)
SELECT id, email, password_hash, full_name, is_email_verified, default_tenant_id, created_at, updated_at, mfa_secret, mfa_enabled, failed_login_attempts, locked_until FROM new_user;

