# LaventeCare Auth Systems 🛡️
> **Status**: Production-Ready (Hardened)
> **Security Model**: Zero Trust / "Anti-Gravity" Sentinel

A high-performance, security-first Authentication & Multi-Tenancy backend built for the LaventeCare ecosystem. Designed to be impenetrable, audit-compliant, and strictly typed.

## 🌟 What This System Does (Capabilities)

### 1. Multi-Tenancy (Strict Isolation)
-   **Tenant Isolation**: Data is separated logically via verified Row Level Security (RLS) policies. Even if the application code has a bug, the database prevents cross-tenant data leaks.
-   **Dynamic Context**: Middleware automatically identifies the Tenant based on context and enforces isolation per request.
-   **Role-Based Access (RBAC)**: Supports roles (e.g., `admin`, `user`) scoped to specific tenants.

### 2. Next-Gen Authentication
-   **Secure Tokens**:
    -   **Access Tokens**: Short-lived JWTs (JSON Web Tokens) with strict audience and issuer validation.
    -   **Refresh Tokens**: Long-lived, rotation-enforced session tokens stored in the database.
-   **Token Rotation & Reuse Detection**:
    -   **Rotation**: Every refresh issues a entirely new token family.
    -   **The "Nuclear Option"**: If a consumed (old) token is reused (replay attack), the *entire token family* is immediately revoked on all devices to stop attackers.
    -   **Grace Period**: Handles concurrent UI request race conditions safely without false positives.
-   **MFA (Multi-Factor Authentication)**:
    -   **TOTP**: Standard Time-based One-Time Password (Google Authenticator, Authy).
    -   **Pre-Auth Tokens**: Intermediate tokens proving primary password verification before MFA challenge (Prevents MFA bypass).
    -   **Backup Codes**: Emergency recovery codes, hashed at rest.

### 3. "Anti-Gravity" Security Features
-   **Immutable Audit Logs**: Every critical action (Login, Register, Password Change, Ban) is recorded in an append-only `audit_logs` table with Actor, IP, and Metadata.
-   **GDPR Compliance**: Automated "Janitor" worker purges expired tokens and unaccepted invites hourly.
-   **Crypto-Agility**: Uses `bcrypt` for passwords (tunable work factor) and `SHA-256` for opaque tokens.
-   **Rate Limiting**: Built-in protection against brute-force attacks (Redis-ready).
-   **Input Validation**: Strict typing and sanitization at the gate. Input is considered "toxic" until proven otherwise.

### 4. Developer Experience
-   **Type-Safe Database**: Uses `sqlc` to generate Go code from raw SQL. No ORM magic, no runtime typos.
-   **Structured Logging**: JSON-formatted logs (`slog`) with Correlation IDs (`request_id`) for tracing requests across microservices.
-   **Docker Native**: Full development environment spins up in seconds (`docker compose up`).

---

## 🏗️ Architecture

### Tech Stack
-   **Language**: Go 1.22+
-   **Web Framework**: `go-chi` (Lightweight, idiomatic)
-   **Database**: PostgreSQL 15+ (Extensions: `pgcrypto`, `citext`)
-   **Database Driver**: `pgx` (High performance)
-   **Observability**: Sentry (Error Tracking) + Structured Logging

### Directory Structure
```
/cmd
  /api          # Main REST API entrypoint
  /worker       # Background jobs (The Janitor)
  /migrate      # Database migration tool
/internal
  /api          # HTTP Handlers & Middleware
  /auth         # Core Business Logic (Service Layer)
  /audit        # Audit Logging Logic
  /storage      # Database Access (sqlc generated)
/migrations     # SQL Migration Files
```

---

## 🚀 Getting Started

### Prerequisites
-   Docker & Docker Compose
-   Go 1.22+ (Optional, if running locally without Docker)

### Run It
```bash
# 1. Start Infrastructure (DB, API, Worker)
docker compose up -d --build

# 2. Run Migrations (First time only)
docker compose exec api ./migrate
```

### Usage Examples

**1. Public Registration**
```http
POST /auth/register
{
  "email": "doctor@lavente.care",
  "password": "SecurePassword123!",
  "full_name": "Dr. Jan Jansen"
}
```

**2. Login**
```http
POST /auth/login
{
  "email": "doctor@lavente.care",
  "password": "SecurePassword123!"
}
// Returns: AccessToken, RefreshToken
```

**3. Enable MFA**
```http
POST /auth/mfa/setup
Authorization: Bearer <AccessToken>
// Returns: QR Code & Secret
```

---

## 🛡️ "Anti-Gravity" Pillars
1.  **Input is Toxic**: Never trust headers, bodies, or params. Verify before use.
2.  **Silence is Golden**: Never return internal errors to the client. Log them, return generic 500s.
3.  **Database is a Fortress**: Logic belongs in the database constraints and Go Service layer, not in loose SQL strings.
4.  **Race Conditions are Fatal**: Use Transactions (`pgx.Tx`) and Mutexes where state is shared.
