-- Remove Showcase fields from tenants table
DROP INDEX IF EXISTS idx_tenants_is_featured;

ALTER TABLE tenants
DROP COLUMN IF EXISTS logo_url,
DROP COLUMN IF EXISTS is_featured,
DROP COLUMN IF EXISTS category,
DROP COLUMN IF EXISTS description;
