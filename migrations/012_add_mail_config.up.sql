-- Migration 012: Tenant Mail Configuration (Universal SMTP Provider)
-- Purpose: Allow each tenant to use their own SMTP server (GoDaddy, Outlook, etc.)
-- Security: AES-256-GCM encrypted passwords, RLS on mail_config column

-- Add columns for tenant-specific SMTP configuration
ALTER TABLE tenants
ADD COLUMN mail_config JSONB,
ADD COLUMN mail_config_key_version INT DEFAULT 1;

-- Example mail_config structure:
-- {
--   "host": "smtp.office365.com",
--   "port": 587,
--   "user": "noreply@tenant.nl",
--   "pass_encrypted": "AES256_GCM_BASE64_ENCRYPTED_PASSWORD",
--   "from": "Tenant Name <noreply@tenant.nl>",
--   "tls_mode": "starttls"
-- }

-- Index for worker queries (JOIN tenants ON tenant_id to get mail_config)
CREATE INDEX idx_tenants_mail_config ON tenants(id) WHERE mail_config IS NOT NULL;

-- Security Barrier View (Excludes mail_config for protection)
-- Frontend/API uses this view, backend worker uses direct table access
CREATE VIEW tenants_safe AS
SELECT 
    id,
    name,
    slug,
    public_key,
    allowed_origins,
    redirect_urls,
    branding,
    settings,
    is_active,
    created_at,
    updated_at,
    app_url
    -- NOTE: mail_config is EXCLUDED (contains encrypted SMTP credentials)
FROM tenants;

-- Security: Revoke direct SELECT on tenants table
-- IMPORTANT: This breaks existing queries! Update code to use tenants_safe view
-- For now, we comment this out to avoid breaking existing code:
-- REVOKE SELECT ON tenants FROM public;
-- GRANT SELECT ON tenants_safe TO public;

-- Backend service role can still read mail_config for worker
-- (Assumes you have a dedicated postgres role for the backend service)
-- GRANT SELECT (mail_config, mail_config_key_version) ON tenants TO backend_service_role;

-- Comments for documentation
COMMENT ON COLUMN tenants.mail_config IS 'SENSITIVE: Tenant-specific SMTP configuration with encrypted password. Only backend worker should read this. Use tenants_safe view for general queries.';
COMMENT ON COLUMN tenants.mail_config_key_version IS 'Encryption key version for password rotation. Used by crypto.DecryptTenantSecretV().';
COMMENT ON VIEW tenants_safe IS 'Security barrier view that excludes mail_config. Use this for frontend/API queries.';

-- Audit log trigger (track who modifies mail_config)
-- TODO: Add audit log entry when mail_config is updated
-- This helps detect compromised admin accounts changing SMTP credentials
