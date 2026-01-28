# Email Gateway - Environment Variables

This document describes the environment variables required for the Email Gateway system.

## 🔐 Encryption Keys

### `TENANT_SECRET_KEY` (REQUIRED)
**Purpose:** Master encryption key for tenant SMTP passwords  
**Format:** 64 hex characters (32 bytes)  
**Generate:**
```bash
openssl rand -hex 32
```
**Example:**
```
TENANT_SECRET_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
```

**Security:**
- Store in Render secrets (never commit to git)
- Rotate periodically (requires re-encryption of all passwords)
- Use `TENANT_SECRET_KEY_V2` for key rotation

### `TENANT_SECRET_KEY_V2` (Optional)
**Purpose:** Rotation key for zero-downtime key migration  
**Usage:** Set this when rotating encryption keys

---

## 📧 System Default SMTP (Fallback)

These settings are used when a tenant hasn't configured custom SMTP.

### `SMTP_HOST`
**Purpose:** Default SMTP server hostname  
**Example:** `smtp.sendgrid.net`

### `SMTP_PORT`
**Purpose:** SMTP port  
**Default:** `587`  
**Allowed:** `25`, `465`, `587`, `2525`

### `SMTP_USER`
**Purpose:** SMTP username  
**Example:** `apikey`

### `SMTP_PASS_ENCRYPTED`
**Purpose:** System SMTP password (encrypted with `TENANT_SECRET_KEY`)  
**Generate:**
```go
// In Go code:
encryptedPass, _ := crypto.EncryptTenantSecret("your-smtp-password")
fmt.Println(encryptedPass)
// Output: enc:base64encodedciphertext
```
**Set in Render:**
```
SMTP_PASS_ENCRYPTED=enc:A3j8Kl2...base64...
```

### `SMTP_FROM`
**Purpose:** Default sender address  
**Example:** `LaventeCare Auth <noreply@laventecare.nl>`

### `SMTP_TLS_MODE`
**Purpose:** TLS connection mode  
**Options:** `starttls` (port 587) or `tls` (port 465)  
**Default:** `starttls`

---

## ⚙️ Email Worker Configuration

### `EMAIL_WORKER_INTERVAL`
**Purpose:** How often the worker polls for new emails  
**Format:** Go duration string  
**Default:** `5s`  
**Example:** `10s`, `30s`, `1m`

### `EMAIL_WORKER_BATCH_SIZE`
**Purpose:** Maximum emails to process per poll  
**Default:** `10`  
**Recommended:** `5-20` (depends on SMTP server speed)

### `EMAIL_SEND_TIMEOUT`
**Purpose:** Maximum time per email send (prevents worker starvation)  
**Format:** Go duration string  
**Default:** `15s`  
**Recommended:** `10s-20s`

### `EMAIL_DNS_TIMEOUT`
**Purpose:** DNS lookup timeout (SSRF protection)  
**Format:** Go duration string  
**Default:** `3s`

### `EMAIL_TCP_TIMEOUT`
**Purpose:** TCP handshake timeout  
**Format:** Go duration string  
**Default:** `5s`

---

## 🛡️ Security Configuration

### `SMTP_EGRESS_FILTER_ENABLED`
**Purpose:** Enable SSRF protection (block private IPs)  
**Default:** `true`  
**Recommended:** Always `true` in production

### `SMTP_ALLOWED_PORTS`
**Purpose:** Restrict SMTP ports (port scanning prevention)  
**Default:** `25,465,587,2525`  
**Format:** Comma-separated list

---

## 📊 Complete Example (Render.com)

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/db

# Core Auth Settings
JWT_SECRET=your-jwt-secret-here

# Email Gateway - Encryption
TENANT_SECRET_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4

# Email Gateway - System Default SMTP (SendGrid Example)
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS_ENCRYPTED=enc:A3j8Kl2mP9qR7sT1vW4xY6zA2bC5dE8fG0hI3jK6lM9nO2pQ5rS8tU1vX4yZ7
SMTP_FROM=LaventeCare Auth <noreply@laventecare.nl>
SMTP_TLS_MODE=starttls

# Email Worker Settings
EMAIL_WORKER_INTERVAL=5s
EMAIL_WORKER_BATCH_SIZE=10
EMAIL_SEND_TIMEOUT=15s

# Security
SMTP_EGRESS_FILTER_ENABLED=true
SMTP_ALLOWED_PORTS=25,465,587,2525
```

---

## 🔄 Key Rotation Workflow

When rotating `TENANT_SECRET_KEY`:

1. **Generate new key:**
   ```bash
   openssl rand -hex 32
   ```

2. **Add V2 key to Render:**
   ```bash
   TENANT_SECRET_KEY_V2=<new-key>
   ```

3. **Deploy with both keys active**

4. **Background job re-encrypts all tenant configs:**
   ```go
   // Pseudo-code
   for each tenant with mail_config:
       oldPassword = crypto.DecryptTenantSecretV(config.PassEncrypted, 1)
       newPassword = crypto.EncryptTenantSecret(oldPassword)
       update tenants set mail_config = newPassword, mail_config_key_version = 2
   ```

5. **Remove old key:**
   ```bash
   # After all configs migrated
   rm TENANT_SECRET_KEY
   mv TENANT_SECRET_KEY_V2 TENANT_SECRET_KEY
   ```

---

## ⚠️ Security Warnings

1. **Never log decrypted passwords** - The decrypted password only exists in memory during SMTP send
2. **Never commit keys to git** - Use Render secrets management
3. **Rotate keys periodically** - Recommended: every 90 days
4. **Monitor failed decryption attempts** - Could indicate key corruption or attack
5. **Backup encryption keys** - Store securely offline (e.g., password manager with org account)
