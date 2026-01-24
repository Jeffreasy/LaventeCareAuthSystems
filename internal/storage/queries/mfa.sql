-- name: CreateBackupCode :exec
INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ($1, $2);

-- name: CreateBackupCodes :copyfrom
INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ($1, $2);

-- name: GetBackupCode :one
SELECT * FROM mfa_backup_codes
WHERE user_id = $1 AND code_hash = $2 AND used = FALSE
LIMIT 1;

-- name: ConsumeBackupCode :exec
UPDATE mfa_backup_codes
SET used = TRUE, used_at = NOW()
WHERE id = $1;

-- name: CountRemainingBackupCodes :one
SELECT count(*) FROM mfa_backup_codes
WHERE user_id = $1 AND used = FALSE;

-- name: DeleteBackupCodes :exec
DELETE FROM mfa_backup_codes
WHERE user_id = $1;
