# Render Deployment Guide

> **Complete step-by-step guide for deploying LaventeCare Auth Systems to Render**

## 📋 Prerequisites

Before deploying, ensure you have:

- ✅ A [Render account](https://dashboard.render.com/register) (free tier available)
- ✅ This repository pushed to GitHub
- ✅ Generated secrets (use `./scripts/generate-secrets.ps1`)
- ✅ Basic understanding of PostgreSQL and environment variables

---

## 🚀 Quick Start (Blueprint Deployment)

The fastest way to deploy is using Render's **Infrastructure-as-Code** blueprint.

### Step 1: Connect Repository

1. Login to [Render Dashboard](https://dashboard.render.com)
2. Click **"New"** → **"Blueprint"**
3. Connect your GitHub account (if not already connected)
4. Select the `LaventeCareAuthSystems` repository
5. Click **"Connect"**

### Step 2: Configure Blueprint

Render will automatically detect the `render.yaml` file and show you:

- **laventecare-db**: PostgreSQL 16 database (Starter plan, $7/month)
- **laventecare-api**: Web Service (Auto-deployed from `main` branch)
- **laventecare-worker**: Background Worker (Janitor service)
- **laventecare-email-worker**: Background Worker (Email Gateway)

**Review the configuration** and click **"Apply"**.

### Step 3: Set Environment Secrets

After deployment starts, you need to add secrets:

1. Navigate to **laventecare-api** service → **Environment** tab
2. Add the following environment variables:

| Variable | Value | Notes |
|----------|-------|-------|
| `JWT_SECRET` | *(generated)* | Run `./scripts/generate-secrets.ps1` |
| `APP_URL` | `https://laventecare-api.onrender.com` | Update with your Render URL |
| `SENTRY_DSN` | *(optional)* | Only if using Sentry |

3. **Email Worker Secrets**: Navigate to **laventecare-email-worker** and add:
   - `TENANT_SECRET_KEY` (Generated via scripts)
   - SMTP Credentials (`SMTP_HOST`, `SMTP_USER`, etc.) as defined in [Email Gateway Guide](./email_gateway.md).

4. Click **"Save Changes"** (triggers redeployment)

### Step 4: Verify Deployment

Wait 5-10 minutes for the initial deployment. Then verify:

```bash
# Check API health
curl https://your-render-url.onrender.com/health

# Expected output:
# {"status":"healthy"}
```

✅ **You're live!** The API is now accessible at your Render URL.

---

## 🔧 Manual Deployment (Alternative)

If you prefer manual setup instead of the blueprint:

### 1. Create PostgreSQL Database

1. Dashboard → **"New+"** → **"PostgreSQL"**
2. Name: `laventecare-db`
3. Database: `laventecare`
4. Plan: **Starter** ($7/month)
5. Region: **Frankfurt** (or closest to your users)
6. Click **"Create Database"**

**Save the connection details** (you'll need them for services).

### 2. Deploy API Web Service

1. Dashboard → **"New+"** → **"Web Service"**
2. Connect your GitHub repository
3. Configure:
   - **Name**: `laventecare-api`
   - **Region**: Same as database (Frankfurt)
   - **Branch**: `main`
   - **Build Command**: *(Auto-detected from Dockerfile)*
   - **Start Command**: *(Uses ENTRYPOINT from Dockerfile)*
   - **Plan**: Starter ($7/month)

4. **Environment Variables**:
   ```
   APP_ENV=production
   PORT=8080
   DATABASE_URL=[Link to laventecare-db]
   JWT_SECRET=[Generated secret]
   APP_URL=https://your-url.onrender.com
   ALLOW_PUBLIC_REGISTRATION=false
   ```

5. **Health Check Path**: `/health`
6. Click **"Create Web Service"**

### 3. Deploy Worker Service (Janitor)

1. Dashboard → **"New+"** → **"Background Worker"**
2. Connect same repository
3. Configure:
   - **Name**: `laventecare-worker`
   - **Region**: Same as database
   - **Branch**: `main`
   - **Docker Command**: `./worker`
   - **Plan**: Starter ($7/month)

4. **Environment Variables**:
   ```
   APP_ENV=production
   DATABASE_URL=[Link to laventecare-db]
   ```

5. Click **"Create Background Worker"**

### 4. Deploy Email Worker

See [Email Gateway Deployment Guide](./email_gateway.md) for detailed manual steps.

---

## 🧪 Testing Your Deployment

### 1. Health Check

```bash
curl https://your-api.onrender.com/health
```

**Expected**: `{"status":"healthy"}`

### 2. Test Registration (if enabled)

```bash
curl -X POST https://your-api.onrender.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePassword123!",
    "full_name": "Test User"
  }'
```

**Expected**: JSON with `accessToken` and `refreshToken`.

### 3. Verify Migrations

1. Go to Render Dashboard → **laventecare-api** → **Shell**
2. Run:
   ```bash
   psql $DATABASE_URL -c "\dt"
   ```

**Expected**: List of tables (`users`, `tenants`, `refresh_tokens`, `audit_logs`, etc.)

### 4. Check Worker Logs

1. Go to **laventecare-worker** → **Logs**
2. Look for:
   ```
   🧹 Janitor Worker Started
   Running cleanup cycle...
   Cleaned refresh_tokens: X deleted
   ```

---

## 🔐 Security Hardening

After deployment, verify the following **Anti-Gravity** security posture:

### SSL/TLS
- ✅ All endpoints use HTTPS (automatic via Render)
- ✅ No HTTP fallback allowed

### Secrets
```bash
# Verify secrets are set (in Render Dashboard → Environment)
✓ JWT_SECRET (minimum 32 characters)
✓ DATABASE_URL (auto-injected)
✓ ALLOW_PUBLIC_REGISTRATION (set to false for production)
```

### Database Security
```bash
# Verify RLS (Row Level Security) is active
psql $DATABASE_URL -c "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';"

# Expected: rowsecurity = true for users, tenants, etc.
```

### Rate Limiting
```bash
# Test rate limiter (should block after burst)
for i in {1..15}; do curl https://your-api.onrender.com/health; done

# Expected: HTTP 429 after ~10 requests
```

### Audit Logs
```bash
# Verify audit logs are working
psql $DATABASE_URL -c "SELECT COUNT(*) FROM audit_logs;"

# Expected: > 0 (after some API activity)
```

---

## 📊 Monitoring & Observability

### Render Dashboard

1. **Metrics**: Dashboard → Service → **Metrics** tab
   - CPU usage
   - Memory usage
   - Request count
   - Response times

2. **Logs**: Dashboard → Service → **Logs** tab
   - Real-time structured JSON logs
   - Filter by severity (`INFO`, `WARN`, `ERROR`)

### Sentry Integration (Optional)

If you configured `SENTRY_DSN`:

1. Go to [Sentry Dashboard](https://sentry.io)
2. Check for errors in your project
3. Set up alerts for critical errors

### Database Monitoring

1. Dashboard → **laventecare-db** → **Metrics**
   - Connection count
   - Query performance
   - Storage usage

---

## 🔄 Updating Your Deployment

### Automatic Deployments (Recommended)

Render auto-deploys when you push to `main`:

```bash
git add .
git commit -m "Update: feature X"
git push origin main
```

Render will:
1. Detect the push
2. Build new Docker image
3. Run migrations (via `docker-entrypoint.sh`)
4. Perform rolling deployment (zero downtime)

### Manual Deployment

1. Dashboard → **laventecare-api** → **Manual Deploy**
2. Select branch: `main`
3. Click **"Deploy"**

---

## 🐛 Troubleshooting

### Issue: "Database unavailable" in health check

**Cause**: Database connection failed.

**Solution**:
1. Check **DATABASE_URL** is correctly set
2. Verify database service is running
3. Check logs: Dashboard → laventecare-db → Logs

### Issue: Migrations not running

**Cause**: `docker-entrypoint.sh` not executable.

**Solution**:
The Dockerfile already sets `chmod +x`. If still failing:
1. Go to **Shell** in Render Dashboard
2. Run manually:
   ```bash
   ./migrate
   ```

### Issue: JWT tokens not working

**Cause**: `JWT_SECRET` not set or changed.

**Solution**:
1. Verify `JWT_SECRET` in Environment tab
2. If changed, all existing tokens are invalidated (expected)

### Issue: Worker not cleaning up tokens

**Cause**: Worker may not be running.

**Solution**:
1. Check **laventecare-worker** status
2. Review logs for errors
3. Verify `DATABASE_URL` is set

### Issue: "Service Unavailable" (503)

**Cause**: Health check failing.

**Solution**:
1. Check **Logs** for errors
2. Verify database is reachable
3. Check if migrations completed

---

## 💰 Cost Breakdown

**Minimal Production Setup:**

| Service | Plan | Cost/Month |
|---------|------|------------|
| PostgreSQL Database | Starter | $7 |
| API Web Service | Starter | $7 |
| Janitor Worker | Starter | $7 |
| Email Worker | Starter | $7 |
| **Total** | | **$28** |

**Scaling Options:**

- **Free Tier**: Available for testing (services sleep after inactivity)
- **Standard Database** ($20/month): For >1000 users or high traffic
- **Autoscaling**: API can scale horizontally (additional $7/instance)

---

## 🎯 Next Steps

After successful deployment:

1. ✅ **Configure Custom Domain** (optional)
   - Dashboard → Service → Settings → Custom Domain
   - Add your domain (e.g., `auth.laventecare.nl`)
   - Update DNS records

2. ✅ **Set up Backups**
   - Render includes automatic daily backups for PostgreSQL
   - Configure retention: Database → Settings → Backups

3. ✅ **Enable Alerts**
   - Dashboard → Service → Notifications
   - Add email/Slack for downtime alerts

4. ✅ **Review Security**
   - Run security audit (see checklist in implementation_plan.md)
   - Test all authentication flows
   - Verify audit logs are capturing events

5. ✅ **Load Testing** (recommended)
   - Use tools like `k6` or `Apache Bench`
   - Verify performance under load
   - Adjust scaling if needed

---

## 📚 Additional Resources

- 📖 [Render Documentation](https://render.com/docs)
- 🔐 [LaventeCare Security Guide](./security_auth.md)
- 🏗️ [Architecture Overview](./architecture.md)
- 🔧 [Operations Guide](./operations.md)

---

**Need Help?**

- 💬 [Render Community](https://community.render.com)
- 📧 Support: support@render.com
- 🐛 Issues: Open a GitHub issue in this repository
