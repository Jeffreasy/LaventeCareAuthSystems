-- 1. List all valid tenants
SELECT id, name, slug FROM tenants;

-- 2. Check for orphaned REFRESH TOKENS (Direct cause of FK violation if constraint was missing before)
SELECT * FROM refresh_tokens WHERE tenant_id NOT IN (SELECT id FROM tenants);

-- 3. Check for orphaned USERS (Root cause of the crash path)
-- If a user exists with a tenant_id that isn't in tenants, Login finds them but crashes on token insert.
SELECT id, email, tenant_id FROM users WHERE tenant_id NOT IN (SELECT id FROM tenants);
