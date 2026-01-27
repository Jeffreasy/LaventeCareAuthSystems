-- Audit Logs Queries
-- Read-only queries for audit log API (writes handled by audit service)

-- name: ListAuditLogs :many
SELECT 
    id,
    timestamp,
    actor_id,
    session_id,
    tenant_id,
    action,
    target_id,
    metadata,
    ip_address,
    user_agent,
    request_id
FROM audit_logs
WHERE tenant_id = $1
ORDER BY timestamp DESC
LIMIT $2 OFFSET $3;

-- name: GetAuditLogsByUser :many
SELECT 
    id,
    timestamp,
    actor_id,
    session_id,
    tenant_id,
    action,
    target_id,
    metadata,
    ip_address,
    user_agent,
    request_id
FROM audit_logs
WHERE tenant_id = $1 AND actor_id = $2
ORDER BY timestamp DESC
LIMIT $3 OFFSET $4;

-- name: GetAuditLogsByAction :many
SELECT 
    id,
    timestamp,
    actor_id,
    session_id,
    tenant_id,
    action,
    target_id,
    metadata,
    ip_address,
    user_agent,
    request_id
FROM audit_logs
WHERE tenant_id = $1 AND action = $2
ORDER BY timestamp DESC
LIMIT $3 OFFSET $4;

-- name: CountAuditLogs :one
SELECT COUNT(*) as total
FROM audit_logs
WHERE tenant_id = $1;
