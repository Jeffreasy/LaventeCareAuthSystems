# Email Gateway Deployment Guide

Deze guide beschrijft hoe je de **LaventeCare Email Gateway** deployt op Render.com met multi-tenant SMTP support.

---

## 📋 Prerequisites

1. ✅ Migrations `010`, `011`, `012` zijn toegepast
2. ✅ `TENANT_SECRET_KEY` is gegenereerd (zie hieronder)
3. ✅ System default SMTP credentials zijn geconfigureerd

---

## 🔐 Stap 1: Generate Encryption Key

De `TENANT_SECRET_KEY` is nodig om tenant SMTP passwords te encrypten.

### Lokaal (PowerShell):
```powershell
# Generate 32-byte AES key
$bytes = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$key = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ''
Write-Host "TENANT_SECRET_KEY=$key"
```

### Lokaal (Bash/Linux):
```bash
openssl rand -hex 32
```

**Kopieer de output** - deze heb je nodig voor Render secrets.

---

## 🚀 Stap 2: Deploy Email Worker op Render

### 2.1 Create New Background Worker

1. Ga naar **Render Dashboard**
2. Click **"New +"** → **"Background Worker"**
3. Select je **LaventeCareAuthSystems** repository

### 2.2 Configure Worker

**Basic Settings:**
- **Name:** `laventecare-email-worker`
- **Environment:** `Go`
- **Region:** Same as API (e.g., `Frankfurt (EU Central)`)
- **Branch:** `main`

**Build \u0026 Deploy:**
- **Build Command:**
  ```bash
  go build -o emailworker ./cmd/emailworker
  ```
- **Start Command:**
  ```bash
  ./emailworker
  ```

**Instance Type:**
- **Free Tier:** Starter ($7/month) - Goed voor ~1000 emails/dag
- **Production:** Starter Plus ($25/month) - Tot ~10,000 emails/dag

### 2.3 Environment Variables

Voeg deze secrets toe via **Environment** tab:

```bash
# Database (same as API)
DATABASE_URL=$DATABASE_URL  # From internal database connection

# Encryption Key (CRITICAL!)
TENANT_SECRET_KEY=<paste-generated-key-here>

# Worker Configuration
EMAIL_WORKER_INTERVAL=5s
EMAIL_WORKER_BATCH_SIZE=10
EMAIL_SEND_TIMEOUT=15s

# System Default SMTP (Fallback for tenants without custom config)
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS_ENCRYPTED=<encrypted-password-see-below>
SMTP_FROM=LaventeCare Auth <noreply@laventecare.nl>
SMTP_TLS_MODE=starttls

# Security
SMTP_EGRESS_FILTER_ENABLED=true
SMTP_ALLOWED_PORTS=25,465,587,2525
```

### 2.4 Encrypt System SMTP Password

**Lokaal (Go):**
```go
// Create file: cmd/encryptpass/main.go
package main

import (
    "fmt"
    "os"
    "github.com/Jeffreasy/LaventeCareAuthSystems/internal/crypto"
)

func main() {
    // Set your TENANT_SECRET_KEY
    os.Setenv("TENANT_SECRET_KEY", "YOUR_KEY_HERE")
    
    // Encrypt your SendGrid/SMTP password
    encrypted, _ := crypto.EncryptTenantSecret("your-smtp-password")
    fmt.Println("SMTP_PASS_ENCRYPTED=" + encrypted)
}
```

Run:
```bash
go run cmd/encryptpass/main.go
```

Kopieer de output naar `SMTP_PASS_ENCRYPTED` in Render.

---

## 📊 Stap 3: Verify Deployment

### 3.1 Check Worker Logs

In Render Dashboard → **laventecare-email-worker** → **Logs**:

```
📧 Email Worker started, polling for emails...
Worker configured poll_interval=5s batch_size=10
```

### 3.2 Test Email Sending

**Via API (cURL):**
```bash
# Invite user (triggers email)
curl -X POST https://api.laventecare.nl/api/v1/admin/users/invite \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","role":"admin"}'
```

**Check Logs:**
```
Email sent successfully id=xxx tenant_id=xxx template=invite_user to_hash=sha256... provider_msg_id=<...>
```

### 3.3 Monitor Queue

**Check Dashboard:**
```bash
curl -X GET https://api.laventecare.nl/api/v1/admin/email-stats \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID"
```

**Response:**
```json
{
  "queue": {
    "pending": 0,
    "processing": 0,
    "sent": 12,
    "failed": 0
  },
  "delivery": {
    "delivered": 10,
    "bounced": 1,
    "spam": 0
  }
}
```

---

## 🔧 Stap 4: Configure Tenant Custom SMTP

Tenants kunnen hun eigen SMTP server configureren (GoDaddy, Outlook, etc.).

**API Request:**
```bash
curl -X POST https://api.laventecare.nl/api/v1/admin/mail-config \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "smtp.office365.com",
    "port": 587,
    "user": "noreply@klant.nl",
    "password": "PlaintextPasswordHere",
    "from": "Klant Naam <noreply@klant.nl>",
    "tls_mode": "starttls"
  }'
```

**Verification:**
- Password wordt automatisch encrypted via AES-256-GCM
- SSRF check valideert dat host geen private IP is
- Port wordt gevalideerd (alleen 25, 465, 587, 2525 toegestaan)

---

## 🚨 Troubleshooting

### Worker Crashes op Start

**Error:** `TENANT_SECRET_KEY not set`  
**Fix:** Add secret via Render Environment tab

**Error:** `Failed to connect to database`  
**Fix:** Check `DATABASE_URL` is correct (use internal database URL)

### Emails Stuck in Queue

**Check Worker Logs:**
```
Email processing failed ... SMTP timeout (slow server)
```
**Possible Causes:**
- SMTP server is down
- Firewall blocking outbound port 587
- Invalid credentials

**Debug:**
```sql
-- Check failed emails
SELECT id, last_error, retry_count, next_retry_at
FROM email_outbox
WHERE status = 'failed' OR retry_count > 0
ORDER BY created_at DESC
LIMIT 10;
```

### SSRF Blocked

**Log:**
```
SSRF attempt blocked in mail config ... host=192.168.1.1
```
**This is expected!** De security controls werken correct.  
**Fix:** Gebruik een public SMTP server (niet internal IPs).

---

## 🔄 Key Rotation

Wanneer je `TENANT_SECRET_KEY` wilt roteren:

1. **Generate new key**
2. **Add to Render:**
   ```
   TENANT_SECRET_KEY_V2=<new-key>
   ```
3. **Deploy worker with both keys**
4. **Background script re-encrypts all configs:**
   ```sql
   -- Find all tenants with mail_config
   SELECT id, mail_config FROM tenants WHERE mail_config IS NOT NULL;
   ```
5. **Update each tenant**:
   ```go
   // Decrypt with V1, re-encrypt with V2
   oldPass := crypto.DecryptTenantSecretV(config.PassEncrypted, 1)
   newPass := crypto.EncryptTenantSecret(oldPass)
   // Update DB with new encrypted password + version = 2
   ```
6. **Remove old key** after migration complete

---

## 📊 Monitoring Checklist

✅ **Worker Health:** Logs show "Email Worker started"  
✅ **Queue Processing:** `email_outbox` table has `status='sent'` entries  
✅ **No Stuck Emails:** `SELECT COUNT(*) FROM email_outbox WHERE status='processing' AND processing_started_at < NOW() - INTERVAL '5 minutes'` → Should be 0  
✅ **Delivery Rate:** Check `email_logs` table for bounce/spam rate  
✅ **SSRF Blocks:** Monitor logs for "SSRF attempt blocked" (should be rare)

---

## 💰 Cost Estimate

**Render.com:**
- **Email Worker:** $7/month (Starter) or $25/month (Starter Plus)
- **Database:** $7/month (Starter) - Shared with API
- **Total:** ~$14-32/month

**External SMTP (Optional):**
- **SendGrid:** Free tier = 100 emails/dag
- **Postmark:** $15/month = 10,000 emails
- **AWS SES:** $0.10 per 1,000 emails

---

## 🎯 Production Checklist

- [x] Migrations `010`, `011`, `012` applied
- [x] `TENANT_SECRET_KEY` generated and set in Render
- [x] System default SMTP configured and tested
- [x] Email Worker deployed and running
- [x] Test email sent successfully
- [x] Queue stats endpoint returns valid data
- [x] Admin can configure custom SMTP via API
- [x] SSRF protection validated (try localhost → should fail)
- [x] Monitor setup for failed emails
- [x] Backup encryption keys stored securely
