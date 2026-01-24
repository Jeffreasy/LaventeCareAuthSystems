-- name: CreateAuditLog :exec
INSERT INTO audit_logs (
    actor_id, 
    session_id, 
    tenant_id, 
    action, 
    target_id, 
    metadata, 
    ip_address, 
    user_agent, 
    request_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
);

-- name: ListAuditLogsByTenant :many
SELECT * FROM audit_logs
WHERE tenant_id = $1
ORDER BY timestamp DESC
LIMIT $2 OFFSET $3;

-- name: ListAuditLogsByUser :many
SELECT * FROM audit_logs
WHERE actor_id = $1
ORDER BY timestamp DESC
LIMIT $2 OFFSET $3;
