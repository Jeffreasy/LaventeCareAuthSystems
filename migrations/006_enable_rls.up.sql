-- Phase 35: Enable Row Level Security (Hardened Isolation)

-- 1. Enable RLS on sensitive tables
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;

-- 2. Create Policies
-- Note: 'app.current_tenant' must be set in the transaction by the application.

-- MEMBERSHIPS: Only visible to the tenant context (or System Admin bypass if implemented later)
CREATE POLICY tenant_isolation_memberships ON memberships
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);

-- INVITATIONS:
-- A. Tenant Isolation: Visible to tenant admins
CREATE POLICY tenant_isolation_invitations ON invitations
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);

-- B. Public Lookup: Allow finding invitation by Hash (for Registration flow)
-- This Policy allows SELECT on ALL rows if the query filters by token_hash.
-- Postgres RLS doesn't easily support "Column based filter" constraints in USING without leakage.
-- Safe approach: For MVP, we allow public lookup of invitations via function or just rely on hash entropy.
-- Actually, for `GetInvitationByHash`, we need access.
-- We add a policy that allows access if `token_hash` matches? No, we can't reference new row in SELECT.
-- We will rely on Application Level "Bypass" (Super User) for the specific GetInvitation query OR
-- We grant SELECT to public on invitations but rely on the uniqueness of the hash (Security by Unpredictability).
-- Better: We create a function `get_invitation(hash)` with SECURITY DEFINER.
-- But for this migration, we add a permissive policy for SELECT specific to token verification?
-- No, that opens enumeration.
-- DECISION: We DO NOT enable RLS on invitations for SELECT yet, or we provide a Bypass Policy for now.
-- Policy: "Allow All Select" (But restricted by layout?). No.
-- We will skip RLS on invitations for this immediate step to avoid breaking `validate_invitation` logic,
-- and focus on `memberships` which is the critical data leak vector.

-- Removing invitations RLS from this block to prevent breakage until strict context switching is implemented.
ALTER TABLE invitations DISABLE ROW LEVEL SECURITY;

-- 3. REFRESH TOKENS: Enable RLS
-- Critical: Sessions contain user credentials and must be strictly isolated per tenant.
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_refresh_tokens ON refresh_tokens
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);

-- 4. Audit Logs RLS moved to 007 (Table Creation)

-- ----------------------------
-- HOW TO USE THIS RLS SETUP
-- ----------------------------
-- The application MUST set the session variable in every transaction via:
--   SELECT set_config('app.current_tenant', '<tenant_uuid>', true)
--
-- Use the helper functions in internal/storage/db_context.go:
--   - WithTenantContext(ctx, pool, tenantID, fn) for tenant-scoped operations
--   - WithoutRLS(ctx, pool, fn) for system operations (audit writes, janitor cleanup)
--
-- Tables with RLS ENABLED: memberships, refresh_tokens, audit_logs
-- Tables WITHOUT RLS: invitations, verification_tokens (public lookup required), users, tenants
 
