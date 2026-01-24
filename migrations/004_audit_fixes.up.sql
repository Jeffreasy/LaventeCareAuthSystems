/*
 * ----------------------------------------------
 * PHASE 30: AUDIT REMEDIATION
 * Critical Schema Fixes Discovered During Documentation Audit
 * ----------------------------------------------
 */

-- Fix Critical Finding #2: Missing 'accepted' column in invitations
-- Issue: SQLC queries expect this column for invitation acceptance flow
-- Impact: Without this, GetInvitationByHash and AcceptInvitation queries fail at runtime
ALTER TABLE invitations 
ADD COLUMN IF NOT EXISTS accepted BOOLEAN NOT NULL DEFAULT FALSE;

-- Fix Critical Finding #3: Missing 'revoked_at' column in refresh_tokens
-- Issue: Janitor worker cleanup query expects this for purging old revoked tokens
-- Impact: Without this, CleanExpiredRefreshTokens crashes with "column does not exist"
ALTER TABLE refresh_tokens 
ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- Performance Index: Speed up cleanup queries
-- The worker scans by revoked_at hourly. Without index, this becomes O(n) table scan.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked_at 
ON refresh_tokens(revoked_at) 
WHERE revoked_at IS NOT NULL;
