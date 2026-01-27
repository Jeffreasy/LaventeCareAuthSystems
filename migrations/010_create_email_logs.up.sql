-- Migration 010: Email Logs (Audit Trail for Email Delivery)
-- Purpose: GDPR-compliant email audit logging with privacy controls
-- Security: RLS enabled, recipient hashes (not raw emails), tenant isolation

CREATE TABLE email_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Privacy: Hash the recipient address (GDPR Art. 32 - Pseudonymization)
    -- SHA256 hash allows duplicate detection without storing PII
    recipient_hash VARCHAR(64) NOT NULL,
    
    -- Template type (restricts to enum for integrity)
    template_type VARCHAR(50) NOT NULL CHECK (template_type IN (
        'invite_user',
        'password_reset',
        'email_verification',
        'mfa_enabled',
        'mfa_disabled',
        'account_locked',
        'password_changed'
    )),
    
    -- Status machine (tracks delivery lifecycle)
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending',
        'sent',
        'failed',
        'bounced',
        'rejected',
        'spam_complaint'
    )),
    
    -- Provider metadata (for debugging, NEVER store full email body)
    provider_msg_id VARCHAR(255),  -- External provider tracking ID
    provider_error TEXT,           -- Error message if failed
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ,
    
    -- Retry tracking (observability)
    retry_count INT NOT NULL DEFAULT 0,
    last_retry_at TIMESTAMPTZ
);

-- Indices for performance (audit queries are read-heavy)
CREATE INDEX idx_email_logs_tenant_id ON email_logs(tenant_id);
CREATE INDEX idx_email_logs_status ON email_logs(status);
CREATE INDEX idx_email_logs_created_at ON email_logs(created_at DESC);
CREATE INDEX idx_email_logs_template_type ON email_logs(template_type);
CREATE INDEX idx_email_logs_recipient_hash ON email_logs(recipient_hash);

-- Composite index for common queries (tenant + status + time range)
CREATE INDEX idx_email_logs_tenant_status_created 
    ON email_logs(tenant_id, status, created_at DESC);

-- Row Level Security (Strict Tenant Isolation)
ALTER TABLE email_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY email_logs_tenant_isolation ON email_logs
    USING (tenant_id::text = current_setting('app.current_tenant', true));

-- Comment for documentation
COMMENT ON TABLE email_logs IS 'Audit trail for all email delivery attempts. Privacy-compliant: stores recipient hashes, not raw emails.';
COMMENT ON COLUMN email_logs.recipient_hash IS 'SHA256 hash of recipient email (GDPR pseudonymization)';
COMMENT ON COLUMN email_logs.provider_msg_id IS 'External SMTP provider message ID for tracking';
