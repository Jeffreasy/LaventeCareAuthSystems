-- name: CreateEmailChangeRequest :one
INSERT INTO email_change_requests (
    user_id, new_email, token_hash, expires_at
) VALUES (
    $1, $2, $3, $4
) RETURNING *;

-- name: GetEmailChangeRequest :one
SELECT * FROM email_change_requests
WHERE token_hash = $1 AND expires_at > NOW() AND used = FALSE
LIMIT 1;

-- name: MarkEmailChangeRequestUsed :exec
UPDATE email_change_requests
SET used = TRUE, used_at = NOW()
WHERE id = $1;

-- name: UpdateUserEmail :exec
UPDATE users
SET email = $2, is_email_verified = TRUE, updated_at = NOW()
WHERE id = $1;
