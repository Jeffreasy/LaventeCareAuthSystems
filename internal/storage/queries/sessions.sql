-- name: GetSessionsByUser :many
SELECT * FROM refresh_tokens
WHERE user_id = $1 AND expires_at > NOW();

-- name: RevokeSession :exec
DELETE FROM refresh_tokens
WHERE id = $1 AND user_id = $2;

-- name: RevokeAllSessions :exec
DELETE FROM refresh_tokens
WHERE user_id = $1;
