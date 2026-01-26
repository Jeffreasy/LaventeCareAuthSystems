-- 009_strict_tenant_isolation.up.sql
-- Enforce Strict Tenant Isolation: User IDENTITY is now Tenant-Scoped.

-- 1. Add tenant_id column (initially nullable to allow backfill)
ALTER TABLE users ADD COLUMN tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

-- 2. Backfill tenant_id from default_tenant_id (Best effort migration)
UPDATE users SET tenant_id = default_tenant_id WHERE tenant_id IS NULL AND default_tenant_id IS NOT NULL;

-- 3. Ruthlessly purge users who are not linked to a tenant (Orphans violate the new law)
DELETE FROM users WHERE tenant_id IS NULL;

-- 4. Enforce NOT NULL
ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;

-- 5. Create new Index for Tenant-Scoped Lookups
CREATE INDEX idx_users_tenant_email ON users(tenant_id, email);

-- 6. Update Constraints
-- Remove global uniqueness of email
ALTER TABLE users DROP CONSTRAINT users_email_key;

-- Add tenant-scoped uniqueness
ALTER TABLE users ADD CONSTRAINT unique_user_email_per_tenant UNIQUE (email, tenant_id);

-- 7. Cleanup
-- default_tenant_id is now redundant as it IS the tenant_id
ALTER TABLE users DROP COLUMN default_tenant_id;
