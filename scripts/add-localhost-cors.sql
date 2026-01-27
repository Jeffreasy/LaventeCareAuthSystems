-- Add localhost to allowed CORS origins for development
-- This allows your Astro dev server to connect to the backend

UPDATE tenants
SET allowed_origins = ARRAY[
    'http://localhost:4321',
    'http://localhost:3000',
    'http://localhost:4322',
    'http://127.0.0.1:4321',
    'https://dekoninklijkeloop.nl',
    'https://www.dekoninklijkeloop.nl'
]
WHERE id = 'c3888c7e-44cf-4827-9a7d-adaae2a1a095';

-- Verify the update
SELECT id, slug, allowed_origins 
FROM tenants 
WHERE id = 'c3888c7e-44cf-4827-9a7d-adaae2a1a095';
