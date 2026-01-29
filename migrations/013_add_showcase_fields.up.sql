-- Add Showcase fields to tenants table
ALTER TABLE tenants
ADD COLUMN IF NOT EXISTS description TEXT,
ADD COLUMN IF NOT EXISTS category VARCHAR(50) DEFAULT 'General',
ADD COLUMN IF NOT EXISTS is_featured BOOLEAN NOT NULL DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS logo_url VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_tenants_is_featured ON tenants(is_featured);
