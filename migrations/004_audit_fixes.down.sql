/*
 * ----------------------------------------------
 * ROLLBACK: PHASE 30 AUDIT FIXES
 * ----------------------------------------------
 */

-- Rollback performance index
DROP INDEX IF EXISTS idx_refresh_tokens_revoked_at;

-- Rollback revoked_at column
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS revoked_at;

-- Rollback accepted column
ALTER TABLE invitations DROP COLUMN IF EXISTS accepted;
