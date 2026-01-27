-- Migration 011: Email Outbox (Async Queue for Worker Processing)
-- Purpose: Decouple email sending from HTTP request lifecycle
-- Security: Prevents SMTP timeout from blocking API, enables retry logic

CREATE TABLE email_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Serialized EmailPayload (JSONB for flexibility)
    -- Structure: {
    --   "to": "user@example.com",
    --   "template": "invite_user",
    --   "data": {"token": "...", "role": "admin"},
    --   "request_id": "sentry-trace-id"
    -- }
    payload JSONB NOT NULL,
    
    -- Status machine (worker picks 'pending', marks 'processing' → 'sent'/'failed')
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending',
        'processing',
        'sent',
        'failed'
    )),
    
    -- Retry logic (exponential backoff: 5m, 10m, 20m)
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 3,
    next_retry_at TIMESTAMPTZ DEFAULT NOW(),  -- When to retry (NULL = immediate)
    
    -- Error tracking
    last_error TEXT,  -- Most recent error message
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processing_started_at TIMESTAMPTZ,  -- When worker picked it up
    processed_at TIMESTAMPTZ,           -- When successfully sent
    
    -- Link to email_logs (after successful send)
    email_log_id UUID REFERENCES email_logs(id) ON DELETE SET NULL
);

-- Indices for worker queue queries
-- CRITICAL: Worker uses "FOR UPDATE SKIP LOCKED" on these indices
CREATE INDEX idx_email_outbox_status ON email_outbox(status);
CREATE INDEX idx_email_outbox_next_retry 
    ON email_outbox(next_retry_at) 
    WHERE status = 'pending';  -- Partial index (only pending items)

-- Composite index for worker query (status + retry time + creation order)
CREATE INDEX idx_email_outbox_worker_queue 
    ON email_outbox(status, next_retry_at, created_at) 
    WHERE status IN ('pending', 'processing');

-- Tenant lookup (for admin dashboard "outgoing mail queue")
CREATE INDEX idx_email_outbox_tenant_id ON email_outbox(tenant_id);

-- Row Level Security (Strict Tenant Isolation)
ALTER TABLE email_outbox ENABLE ROW LEVEL SECURITY;

CREATE POLICY email_outbox_tenant_isolation ON email_outbox
    USING (tenant_id::text = current_setting('app.current_tenant', true));

-- Comments for documentation
COMMENT ON TABLE email_outbox IS 'Async email queue processed by background worker. Enables retry logic and prevents SMTP timeouts from blocking HTTP requests.';
COMMENT ON COLUMN email_outbox.payload IS 'Serialized EmailPayload (JSONB). Contains recipient, template, and data.';
COMMENT ON COLUMN email_outbox.next_retry_at IS 'When to retry sending (exponential backoff). NULL means immediate retry.';
COMMENT ON INDEX idx_email_outbox_worker_queue IS 'Optimized for worker SELECT...FOR UPDATE SKIP LOCKED queries';
