-- 009_strict_tenant_isolation.down.sql
-- Revert Strict Tenant Isolation

-- 1. Restore default_tenant_id
ALTER TABLE users ADD COLUMN default_tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;

-- 2. Backfill default_tenant_id from tenant_id
UPDATE users SET default_tenant_id = tenant_id;

-- 3. Drop Tenant Scoped Constraint
ALTER TABLE users DROP CONSTRAINT unique_user_email_per_tenant;

-- 4. Restore Global Email Uniqueness (WARNING: This will fail if duplicates exist)
-- We cannot safely revert if duplicates were created. 
-- This is a destructive down migration implementation detail.
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);

-- 5. Remove tenant_id
ALTER TABLE users DROP COLUMN tenant_id;

-- 6. Cleanup Index
DROP INDEX IF EXISTS idx_users_tenant_email;
