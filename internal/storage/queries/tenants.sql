-- name: CreateTenant :one
INSERT INTO tenants (
    name, slug, secret_key_hash, allowed_origins, redirect_urls, branding, settings, app_url
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
) RETURNING *;

-- name: GetTenantByID :one
SELECT * FROM tenants
WHERE id = $1 LIMIT 1;

-- name: GetTenantByPublicKey :one
SELECT * FROM tenants
WHERE public_key = $1 LIMIT 1;

-- name: GetTenantBySlug :one
SELECT * FROM tenants
WHERE slug = $1 LIMIT 1;

-- name: UpdateTenantConfig :one
UPDATE tenants
SET 
    allowed_origins = $2,
    redirect_urls = $3,
    branding = $4,
    settings = $5,
    updated_at = NOW(),
    app_url = $6
WHERE id = $1
RETURNING *;

-- name: GetTenantConfig :one
SELECT allowed_origins, app_url FROM tenants
WHERE id = $1;

-- name: ListShowcaseTenants :many
SELECT name, slug, app_url, logo_url, description, category 
FROM tenants 
WHERE is_featured = true 
ORDER BY name ASC;
