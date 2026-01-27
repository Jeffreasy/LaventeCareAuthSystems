-- name: CreateEmailLog :one
-- Creates an audit log entry for email delivery
INSERT INTO email_logs (
    tenant_id,
    recipient_hash,
    template_type,
    status,
    provider_msg_id,
    provider_error,
    sent_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    CASE WHEN $4 = 'sent' THEN NOW() ELSE NULL END
) RETURNING *;

-- name: UpdateEmailLogStatus :exec
-- Updates the status of an email log (e.g., bounced, spam_complaint)
UPDATE email_logs
SET status = $2,
    provider_error = $3
WHERE id = $1;

-- name: GetEmailLogsByTenant :many
-- Dashboard query: Get recent email logs for a tenant
SELECT * FROM email_logs
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: GetEmailLogStats :one
-- Dashboard query: Get email delivery statistics
SELECT 
    COUNT(*) FILTER (WHERE status = 'sent') as sent_count,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_count,
    COUNT(*) FILTER (WHERE status = 'bounced') as bounced_count,
    COUNT(*) FILTER (WHERE status = 'spam_complaint') as spam_count
FROM email_logs
WHERE tenant_id = $1
  AND created_at > $2;

-- name: GetEmailLogByRecipientHash :many
-- Find all emails sent to a specific recipient (for GDPR requests)
SELECT * FROM email_logs
WHERE recipient_hash = $1
ORDER BY created_at DESC;
