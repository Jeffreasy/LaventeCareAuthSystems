-- name: CleanExpiredRefreshTokens :execrows
-- Verwijder tokens die verlopen zijn OF die al langer dan 30 dagen revoked zijn.
DELETE FROM refresh_tokens 
WHERE expires_at < NOW() 
   OR (is_revoked = TRUE AND revoked_at < NOW() - INTERVAL '30 days');

-- name: CleanExpiredVerificationTokens :execrows
-- Wachtwoord-resets en email-verificaties die niet gebruikt zijn.
DELETE FROM verification_tokens 
WHERE expires_at < NOW();

-- name: CleanExpiredInvitations :execrows
-- Uitnodigingen die nooit geaccepteerd zijn.
DELETE FROM invitations 
WHERE expires_at < NOW();

-- name: CleanUsedMfaCodes :execrows
-- Backup codes die al gebruikt zijn (bewaar ze kort voor audit, daarna weg).
DELETE FROM mfa_backup_codes 
WHERE used = TRUE AND used_at < NOW() - INTERVAL '7 days';
