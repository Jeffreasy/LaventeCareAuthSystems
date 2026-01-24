# Deployment Guide

## 🐳 Docker Deployment
The system uses a **Multi-Stage Dockerfile** to build lightweight, production-ready images.

### Services
1.  **API**: The core backend (`/app/main`).
2.  **Worker**: The background janitor (`/app/worker`).
3.  **DB**: PostgreSQL (Version 16+).

### Build & Run
```bash
docker-compose up -d --build
```

This starts:
- `api` on Port 8080
- `worker` (Background process)
- `db` on Port 5432 (internal network)

## ☁️ Environment Variables
Required variables for production (`.env`):

| Variable | Description | Example |
| :--- | :--- | :--- |
| `APP_ENV` | Environment mode | `production` |
| `PORT` | API Listening Port | `8080` |
| `DATABASE_URL` | Postgres Connection String | `postgres://user:pass@host:5432/db` |
| `ALLOW_PUBLIC_REGISTRATION`| Master switch for public signup | `false` |

## 🚀 Production Checklist (Render/AWS)
1.  **Database**: Use a managed PostgreSQL instance (e.g., AWS RDS, Render Managed DB). **Do not use the docker-compose `db` container for production.**
2.  **Secrets**: Inject `DATABASE_URL` via the platform's Secret Manager.
3.  **Migrations**: Run migrations *before* deploying new code.
    ```bash
    # Example (using migrate CLI tool)
    migrate -path migration -database $DATABASE_URL up
    ```
4.  **Worker**: Deploy the `worker` as a separate service/instance to avoid resource contention with the API.
    - Command: `/app/worker`
5.  **Domain**: Configure SSL/TLS termination at your Load Balancer (or Render). The app expects strict HTTPS headers in production.

## 🛡️ Health Checks
- **Liveness**: `GET /health` -> Returns `200 OK`.
