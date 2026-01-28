# Deployment Guide

## 🐳 Docker Deployment
The system uses a **Multi-Stage Dockerfile** to build lightweight, production-ready images.

### Services
1.  **API**: The core backend (`/app/main`).
2.  **Worker**: The background janitor (`/app/worker`).
3.  **Email Worker**: Email queue processor (`/app/emailworker`).
4.  **DB**: PostgreSQL (Version 16+).

### Build & Run
```bash
docker-compose up -d --build
```

This starts:
- `api` on Port 8080
- `worker` (Background process)
- `db` on Port 5432 (internal network)

## ☁️ Render Deployment (Recommended for Production)

**Render provides a fully managed, production-ready platform with zero-config deployments.**

### Quick Start
```bash
# 1. Generate secrets
./scripts/generate-secrets.ps1

# 2. Push to GitHub
git push origin main

# 3. Deploy using Blueprint
# Go to https://dashboard.render.com
# Click "New" → "Blueprint"
# Select your repository
# Render auto-detects render.yaml and deploys all services
```

**📖 See [Render Deployment Guide](./render_deployment_guide.md) for complete instructions.**

### Features
- ✅ **Auto-migrations** on deployment
- ✅ **Zero-downtime** rolling updates
- ✅ **Managed PostgreSQL** with daily backups
- ✅ **Enhanced health checks** (API + Database connectivity)
- ✅ **SSL/TLS** automatic
- ✅ **~$21/month** for production setup

---

## ☁️ Environment Variables
Required variables for production (`.env`):

| Variable | Description | Example |
| :--- | :--- | :--- |
| `APP_ENV` | Environment mode | `production` |
| `PORT` | API Listening Port | `8080` |
| `DATABASE_URL` | Postgres Connection String | `postgres://user:pass@host:5432/db` |
| `ALLOW_PUBLIC_REGISTRATION`| Master switch for public signup | `false` |
| `TENANT_SECRET_KEY` | AES-256 encryption key for SMTP passwords | `a1b2c3d4e5f6...` (64 hex chars) |
| `SMTP_HOST` | Default SMTP server (fallback) | `smtp.sendgrid.net` |
| `SMTP_PORT` | Default SMTP port | `587` |
| `SMTP_FROM` | Default sender address | `noreply@laventecare.nl` |

**🔐 Email Gateway:** See [email_gateway_env.md](./email_gateway_env.md) for complete email configuration.

## 🚀 Production Checklist (Render/AWS)
1.  **Database**: Use a managed PostgreSQL instance (e.g., AWS RDS, Render Managed DB). **Do not use the docker-compose `db` container for production.**
2.  **Secrets**: Inject `DATABASE_URL` via the platform's Secret Manager.
3.  **Migrations**: Run migrations *before* deploying new code.
    ```bash
    # Example (using migrate CLI tool)
    migrate -path migration -database $DATABASE_URL up
    ```
4.  **Workers**: Deploy as separate services to avoid resource contention with the API.
    - **Janitor Worker**: `/app/worker` (Cleans expired tokens, runs hourly)
    - **Email Worker**: `/app/emailworker` (Processes email queue, runs every 5s)
    - Both workers require `DATABASE_URL` and `TENANT_SECRET_KEY`
5.  **Domain**: Configure SSL/TLS termination at your Load Balancer (or Render). The app expects strict HTTPS headers in production.

## 🛡️ Health Checks
- **Liveness & Database Connectivity**: `GET /health`
  - Returns `200 OK` with `{"status":"healthy"}` if API and database are operational
  - Returns `503 Service Unavailable` with `{"status":"unhealthy","error":"service temporarily unavailable"}` if database is unreachable
  - Used by Render for zero-downtime deployments
