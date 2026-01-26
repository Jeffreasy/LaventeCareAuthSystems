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

-- 🔒 APPEND-ONLY ENFORCEMENT (Anti-Gravity Law 4: Integriteit & Verantwoording)
-- Revoke UPDATE and DELETE permissions to guarantee immutability at the database level.
-- Only INSERT and SELECT are permitted on this table.
-- This prevents even privileged application bugs from tampering with audit history.
REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC;
REVOKE UPDATE, DELETE ON audit_logs FROM "user"; -- Default postgres user (see docker-compose.yml)

-- If using a dedicated app_user in production, also revoke for that role:
-- REVOKE UPDATE, DELETE ON audit_logs FROM app_user;

-- 5. RLS: Enable RLS for SELECT only
-- Writes use WithoutRLS pattern (system bypass) to allow cross-tenant audit logging by admin.
-- Reads must be scoped to tenant context to prevent cross-tenant audit log access.
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_audit_logs_read ON audit_logs
    FOR SELECT
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);

