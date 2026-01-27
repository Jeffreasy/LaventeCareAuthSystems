-- name: EnqueueEmail :one
-- Enqueues an email for async processing by the worker
INSERT INTO email_outbox (
    tenant_id,
    payload,
    status,
    next_retry_at
) VALUES (
    $1, $2, 'pending', NOW()
) RETURNING *;

-- name: GetPendingEmails :many
-- Worker query: Fetch pending emails ready for processing
-- Uses FOR UPDATE SKIP LOCKED to prevent race conditions between workers
SELECT * FROM email_outbox
WHERE status = 'pending'
  AND next_retry_at <= NOW()
ORDER BY created_at ASC
LIMIT $1
FOR UPDATE SKIP LOCKED;

-- name: MarkEmailProcessing :exec
-- Marks an email as being processed (prevents duplicate sends)
UPDATE email_outbox
SET status = 'processing',
    processing_started_at = NOW()
WHERE id = $1;

-- name: MarkEmailSent :exec
-- Marks an email as successfully sent
UPDATE email_outbox
SET status = 'sent',
    processed_at = NOW(),
    email_log_id = $2
WHERE id = $1;

-- name: MarkEmailFailed :exec
-- Marks an email as failed and schedules retry
UPDATE email_outbox
SET status = CASE
        WHEN retry_count >= max_retries THEN 'failed'
        ELSE 'pending'
    END,
    retry_count = retry_count + 1,
    last_error = $2,
    next_retry_at = CASE
        WHEN retry_count >= max_retries THEN NULL
        ELSE NOW() + (POWER(2, retry_count) * INTERVAL '5 minutes')
    END
WHERE id = $1;

-- name: GetTenantMailConfig :one
-- Fetches tenant-specific SMTP configuration
-- SECURITY: Only use this in the background worker (has access to encrypted credentials)
SELECT mail_config, mail_config_key_version
FROM tenants
WHERE id = $1 AND mail_config IS NOT NULL;

-- name: UpdateTenantMailConfig :exec
-- Updates tenant SMTP configuration (admin panel)
UPDATE tenants
SET mail_config = $2,
    mail_config_key_version = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: GetOutboxStats :one
-- Dashboard query: Get email queue statistics for a tenant
SELECT 
    COUNT(*) FILTER (WHERE status = 'pending') as pending_count,
    COUNT(*) FILTER (WHERE status = 'processing') as processing_count,
    COUNT(*) FILTER (WHERE status = 'sent') as sent_count,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_count
FROM email_outbox
WHERE tenant_id = $1
  AND created_at > NOW() - INTERVAL '24 hours';
