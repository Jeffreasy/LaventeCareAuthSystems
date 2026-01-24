-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    user_id, token_hash, parent_token_id, family_id, tenant_id, ip_address, user_agent, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
) RETURNING *;

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token_hash = $1 LIMIT 1;

-- name: RotateRefreshToken :one
WITH old_token AS (
    UPDATE refresh_tokens 
    SET is_revoked = TRUE, revoked_at = NOW(), updated_at = NOW()
    WHERE refresh_tokens.token_hash = sqlc.arg(old_token_hash)
    RETURNING id, family_id, user_id, tenant_id
)
INSERT INTO refresh_tokens (
    token_hash, user_id, family_id, parent_token_id, expires_at, ip_address, user_agent, tenant_id
) 
SELECT 
    sqlc.arg(new_token_hash), 
    user_id, 
    family_id, 
    id, 
    sqlc.arg(expires_at),
    sqlc.arg(ip_address),
    sqlc.arg(user_agent),
    tenant_id
FROM old_token
RETURNING *;

-- name: RevokeRefreshTokenFamily :exec
UPDATE refresh_tokens
SET is_revoked = TRUE, revoked_at = NOW(), updated_at = NOW()
WHERE family_id = $1 AND tenant_id = $2;

-- name: RevokeTokenFamily :exec
UPDATE refresh_tokens
SET is_revoked = TRUE, revoked_at = NOW(), updated_at = NOW()
WHERE family_id = (
    SELECT rt.family_id FROM refresh_tokens rt WHERE rt.token_hash = $1
);

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at < NOW();

-- name: CreateVerificationToken :one
INSERT INTO verification_tokens (
    user_id, token_hash, type, tenant_id, expires_at
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetVerificationToken :one
SELECT * FROM verification_tokens
WHERE token_hash = $1 LIMIT 1;

-- name: DeleteVerificationToken :exec
DELETE FROM verification_tokens
WHERE id = $1;
