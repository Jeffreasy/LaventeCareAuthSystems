-- name: GetIoTDeviceByHardwareID :one
SELECT id, tenant_id, secret_hash, is_active 
FROM iot_devices 
WHERE device_id = $1 LIMIT 1;

-- name: UpdateIoTDeviceHeartbeat :exec
UPDATE iot_devices 
SET last_seen_at = NOW() 
WHERE id = $1;

-- name: CreateIoTDevice :one
INSERT INTO iot_devices (
    device_id, tenant_id, secret_hash, name
) VALUES (
    $1, $2, $3, $4
) RETURNING id, created_at;

-- name: ListIoTDevices :many
SELECT * FROM iot_devices 
WHERE tenant_id = $1 
ORDER BY created_at DESC;
