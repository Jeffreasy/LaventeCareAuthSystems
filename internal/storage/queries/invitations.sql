-- name: CreateInvitation :one
INSERT INTO invitations (
    email, token_hash, tenant_id, role, expires_at
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetInvitationByHash :one
SELECT * FROM invitations
WHERE token_hash = $1 AND expires_at > NOW() AND accepted = FALSE
LIMIT 1;

-- name: AcceptInvitation :exec
UPDATE invitations
SET accepted = TRUE
WHERE id = $1;

-- name: GetPendingInvitationsByTenant :many
SELECT * FROM invitations
WHERE tenant_id = $1 AND accepted = FALSE;

-- name: DeleteInvitation :exec
DELETE FROM invitations WHERE token_hash = $1;
