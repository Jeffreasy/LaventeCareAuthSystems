-- Transaction to ensure atomicity
BEGIN;

-- 1. Resolve Tenant ID Dynamically (Safer than hardcoding)
-- Store it in a temp table or just use subqueries
-- We'll use a variable approach via common table expression (CTE)

WITH target_tenant AS (
    SELECT id FROM tenants WHERE slug = 'smartcoolcare'
)
-- 2. Delete Existing User if exists (Scoped to this tenant)
DELETE FROM users 
WHERE email = 'jeffrey@smartcoolcare.nl' 
  AND tenant_id = (SELECT id FROM target_tenant);

-- 3. Insert New User
WITH target_tenant AS (
    SELECT id FROM tenants WHERE slug = 'smartcoolcare'
),
new_user AS (
    INSERT INTO users (
        email, 
        password_hash, 
        full_name, 
        tenant_id, 
        is_email_verified
    ) VALUES (
        'jeffrey@smartcoolcare.nl',
        '$2a$10$tVFrZkEzasKve9WfXXhrS.c6MLDQSI1B3HSlax2Z6g41YmCqz.r5S', -- Oprotten@123
        'Jeffrey Lavente',
        (SELECT id FROM target_tenant), -- Dynamic ID
        TRUE
    ) RETURNING id
)
-- 4. Create Membership (Role: owner)
INSERT INTO memberships (user_id, tenant_id, role)
SELECT id, (SELECT id FROM target_tenant), 'owner'
FROM new_user, target_tenant;

COMMIT;

-- Verification
SELECT u.email, t.slug, t.id 
FROM users u 
JOIN tenants t ON u.tenant_id = t.id 
WHERE u.email = 'jeffrey@smartcoolcare.nl';
