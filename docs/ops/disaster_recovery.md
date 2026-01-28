# Disaster Recovery & Contingency Runbooks

## 🚨 Emergency Protocols
This document outlines the procedures for recovering the **LaventeCare Auth System** from catastrophic failures.

### Scope
- Database Corruption / Data Loss
- Secret Key Leaks (JWT, MFA)
- Infrastructure Failure

---

## 💾 Database Backups & Restore

### Policy
- **Type**: Continuous Archiving (WAL) + Daily Full Snapshots (`pg_dump`).
- **Retention**: 30 Days.
- **Location**: Off-site encrypted storage (e.g., S3 Glacier).
- **Credentials**: Default user is `user` (configured in `docker-compose.yml`).

### 1. Manual Backup (Snapshot)
To trigger an immediate backup (e.g., before big migration):
```bash
# Execute via Docker (safer, versions match)
docker compose exec -T db pg_dump -U user -d laventecare -Fc > backup_$(date +%F_%H%M).dump
```

### 2. Full Restore
**Warning**: This overwrites existing data.
```bash
# 1. Stop API to prevent writes
docker compose stop api

# 2. Reset DB (Safer Option)
docker compose down db
mv postgres_data postgres_data_backup_$(date +%F_%H%M)
docker compose up -d db
# Wait for healthcheck...

# 3. Restore
# Note: You need to pipe the file into the container if checking from host
cat backup_DATE.dump | docker compose exec -T db pg_restore -U user -d laventecare

# 4. Restart API
docker compose start api
```

### 3. Point-in-Time Recovery (PITR)
If using a managed PostgreSQL (RDS/CloudSQL), use the console to restore to a specific timestamp (e.g., "5 minutes before the accidental DELETE").

---

## 🔑 Secret Rotation

### Scenario: `JWT_SECRET` Leak
If the signing key is compromised, all active Access Tokens are untrusted.

1.  **Generate New Secret**: Create a new 32+ char random string.
    ```bash
    openssl rand -hex 32
    ```
2.  **Update Config**: Set `JWT_SECRET` env var to the new value on the server.
3.  **Deploy**: Restart the API service.
    - *Impact*: All existing Access Tokens will immediately fail validation (`signature invalid`). Users will be forced to use Refresh Tokens (if stored securely) or re-login.
4.  **Revoke All Refresh Tokens** (Optional but Recommended):
    - Run SQL: `DELETE FROM refresh_tokens;`
    - *Impact*: Global logout. Everyone must re-authenticate.

### Scenario: MFA Secret Leak (Database Dump)
If the `users` table is leaked including `mfa_secret`:
1.  **Impact**: Attacker can generate TOTP codes if they also have the user's password.
2.  **Mitigation**:
    - Force Password Reset for all users (invalidate sessions).
    - Invalidate `mfa_secret` columns (set to NULL).
    - Notify users to re-enroll in MFA.

---

## 📉 Service Degradation

### Database Unavailability
- **Symptoms**: API returns 500s, logs show "connection refused".
- **Action**:
    1. Check Postgres container status.
    2. Check disk space.
    3. Failover to Read Replica (if configured) for read-only mode.

### High Load (DDoS)
- **Symptoms**: High latency, 503s.
- **Action**:
    1. Tighten Rate Limits (Env var `RATE_LIMIT_RPS`).
    2. Scale API replicas (horizontal scaling).
    3. Enable upstream WAF (Cloudflare/AWS WAF).
