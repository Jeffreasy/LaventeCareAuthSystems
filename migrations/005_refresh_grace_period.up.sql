-- Phase 35: Refresh Token Grace Period (Data Backfill)
-- Column revoked_at was added in 004_audit_fixes.up.sql but might be NULL for existing revoked tokens.

-- Update existing revoked tokens to set revoked_at (approximate) or NULL if valid
UPDATE refresh_tokens SET revoked_at = NOW() WHERE is_revoked = true AND revoked_at IS NULL;
