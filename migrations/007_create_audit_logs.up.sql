-- Phase 36: Audit Logging
-- Immutable record of security-critical events.

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Who performed the action?
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL, -- Keep log even if user deleted
    session_id UUID, -- Link to specific session (refresh token family)
    tenant_id UUID, -- Context
    
    -- What happened?
    action VARCHAR(255) NOT NULL, -- e.g. "auth.login", "user.create"
    target_id UUID, -- Object affected (User ID, Tenant ID, etc.)
    metadata JSONB DEFAULT '{}'::JSONB, -- Contextual details (diffs, etc)
    
    -- Where/How?
    ip_address INET,
    user_agent TEXT,
    request_id TEXT -- Correlation ID from Middleware
);

-- Indexes for Analysis
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
