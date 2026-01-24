-- Add is_revoked column for soft revocation support
ALTER TABLE refresh_tokens 
ADD COLUMN is_revoked BOOLEAN NOT NULL DEFAULT FALSE;

-- Index for fast family lookups (Logout All)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
