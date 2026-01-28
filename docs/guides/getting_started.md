# Getting Started

## 🚀 Zero to Hero

Welcome to the **LaventeCare Auth Systems**. This project assumes you are operating in a hostile environment. Follow these steps to secure your local development station.

### Prerequisites
- **Go**: 1.22+
- **Docker & Docker Compose**: For local PostgreSQL containment.
- **Make**: For command automation.

### Quick Start
1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Jeffreasy/LaventeCareAuthSystems.git
    cd LaventeCareAuthSystems
    ```

2.  **Environment Setup**
    Copy the example environment (if missing, create one):
    ```bash
    # Create a .env file
    cp .env.example .env
    ```
    *See [Configuration](#configuration) for details.*

3.  **Ignition**
    Start the database container:
    ```bash
    docker compose up -d
    ```
    
    Run the application:
    ```bash
    make build
    make run
    ```
    server should listen on port `8080`.

---

## 🔧 Configuration

The application is configured via Environment Variables. In production, these **MUST** be injected securely.

| Variable | Description | Default (Dev) | Criticality |
| :--- | :--- | :--- | :--- |
| `APP_ENV` | Environment mode (`development`/`production`) | `development` | ⚠️ HIGH |
| `PORT` | HTTP Server Port | `8080` | LOW |
| `DATABASE_URL` | PostgreSQL Connection String | `postgres://user:password@localhost:5488/...` | 🚨 CRITICAL |
| `JWT_SECRET` | 32+ char random string for signing tokens | `super-secret...` | 🚨 CRITICAL |
| `SENTRY_DSN` | Sentry Project DSN for telemetry | (empty) | HIGH |
| `ALLOW_PUBLIC_REGISTRATION` | Enable/Disable public sign-ups | `true` | HIGH |
| `APP_URL` | Base URL for email links | `http://localhost:3000` | HIGH |

> **Anti-Gravity Law 1:** Never commit real secrets to Git. The `.env` file is gitignored for a reason.

---

## 🛡️ Core Security Domains

Before diving into code, understand the 4 foundational pillars that make LaventeCare Auth Systems enterprise-grade:

### 1. Identiteitsbeheer (Identity Management)
**What it does:** Securely stores and verifies user identities using battle-tested cryptography.
- **Features**: Bcrypt password hashing (cost 12), JWT Access Tokens (15min lifespan), Refresh Token rotation, Multi-Factor Authentication (TOTP + backup codes), Email verification & password reset flows.
- **Why it matters:** Prevents credential stuffing, password reuse attacks, and ensures only verified identities can access resources.

### 2. Strict Isolation (Multi-Tenancy)
**What it does:** Guarantees that data from different clients/projects is logically separated at the database level.
- **Features**: Every resource belongs to a `tenant`. Users can be members of multiple tenants via the `memberships` table. All queries enforce `tenant_id` filtering. Future: Native PostgreSQL Row Level Security (RLS).
- **Why it matters:** Prevents cross-tenant data leaks (IDOR vulnerabilities) even if application logic has bugs.

### 3. Toegangscontrole (RBAC - Role-Based Access Control)
**What it does:** Fine-grained permission management based on user roles.
- **Features**: 3 roles (`admin`, `editor`, `viewer`) with hierarchical permissions. Role is embedded in JWT claims for zero-latency checks (no database query needed). Middleware enforces role requirements per endpoint.
- **Why it matters:** Ensures users can only perform actions appropriate to their role (principle of least privilege).

### 4. Integriteit & Verantwoording (Audit Logging)
**What it does:** Immutably records every critical action in the system.
- **Features**: Append-only `audit_logs` table with database-level UPDATE/DELETE revocation. Captures actor, action, target, IP, user agent, and metadata. Indexed for fast queries by tenant, user, or action type.
- **Why it matters:** Enables forensic analysis, compliance reporting (GDPR/SOC2), and non-repudiation of actions.

---

## 🐳 Docker Architecture

We use `docker-compose.yml` to orchestrate dependencies.

- **Service: `db`**
    - **Image**: `postgres:16-alpine`
    - **Port**: `5488:5432` (Host:Container). Local connection string should use port **5488**.
    - **Persistence**: Named volume `postgres_data`.
    - **Migrations**: Handled automatically by the `api` service on startup (via `docker-entrypoint.sh`).

To nuke the database and start fresh:
```bash
docker compose down -v
docker compose up -d
```
