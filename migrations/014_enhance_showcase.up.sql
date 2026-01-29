-- Enhance Showcase with professional fields
ALTER TABLE tenants
ADD COLUMN IF NOT EXISTS tagline VARCHAR(120),
ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}',
ADD COLUMN IF NOT EXISTS gallery_urls TEXT[] DEFAULT '{}',
ADD COLUMN IF NOT EXISTS social_links JSONB DEFAULT '{}'::jsonb;

-- Comment for documentation
COMMENT ON COLUMN tenants.tagline IS 'Short catchy description for cards';
COMMENT ON COLUMN tenants.tags IS 'Array of technology or category tags';
COMMENT ON COLUMN tenants.gallery_urls IS 'Array of screenshot URLs';
COMMENT ON COLUMN tenants.social_links IS 'JSON object for external links (twitter, linkedin, etc)';
