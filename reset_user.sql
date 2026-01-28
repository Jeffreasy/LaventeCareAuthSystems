-- Transaction to ensure atomicity
BEGIN;

-- 1. Delete Existing User (Recursively deletes memberships via CASCADE if configured, otherwise manual delete)
DELETE FROM users USING memberships 
WHERE users.id = memberships.user_id 
  AND users.email = 'jeffrey@smartcoolcare.nl' 
  AND memberships.tenant_id = 'b5f25ad8-d419-4127-9ea2-a6e67ed49a1f';

-- Try delete again just in case there was no membership or orphan
DELETE FROM users 
WHERE email = 'jeffrey@smartcoolcare.nl' 
  AND tenant_id = 'b5f25ad8-d419-4127-9ea2-a6e67ed49a1f';

-- 2. Insert New User
WITH new_user AS (
    INSERT INTO users (
        email, 
        password_hash, 
        full_name, 
        tenant_id, 
        is_email_verified
        -- Role removed here, belongs in memberships
    ) VALUES (
        'jeffrey@smartcoolcare.nl',
        '$2a$10$tVFrZkEzasKve9WfXXhrS.c6MLDQSI1B3HSlax2Z6g41YmCqz.r5S', -- Oprotten@123
        'Jeffrey Lavente',
        'b5f25ad8-d419-4127-9ea2-a6e67ed49a1f',
        TRUE
    ) RETURNING id
)
-- 3. Create Membership (Role: owner)
INSERT INTO memberships (user_id, tenant_id, role)
SELECT id, 'b5f25ad8-d419-4127-9ea2-a6e67ed49a1f', 'owner'
FROM new_user;

COMMIT;
