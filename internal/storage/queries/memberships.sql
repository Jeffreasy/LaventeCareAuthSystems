-- name: CreateMembership :one
INSERT INTO memberships (
    user_id, tenant_id, role
) VALUES (
    $1, $2, $3
) RETURNING *;

-- name: GetMembership :one
SELECT role FROM memberships 
WHERE user_id = $1 AND tenant_id = $2;

-- name: GetMembershipsByUser :many
SELECT * FROM memberships
WHERE user_id = $1;

-- name: ListTenantMembers :many
SELECT 
    u.id, 
    u.email, 
    u.full_name, 
    m.role, 
    m.created_at as joined_at
FROM memberships m
JOIN users u ON m.user_id = u.id
WHERE m.tenant_id = $1
ORDER BY m.created_at DESC;

-- name: UpdateMemberRole :exec
UPDATE memberships
SET role = $1, updated_at = NOW()
WHERE user_id = $2 AND tenant_id = $3;

-- name: RemoveMember :exec
DELETE FROM memberships
WHERE user_id = $1 AND tenant_id = $2;
