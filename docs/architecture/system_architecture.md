# System Architecture & Security Model

## 🛡️ The "Anti-Gravity" Security Philosophy
This system is built by the rules of the **Anti-Gravity Sentinel**. We assume hostility in every request. The architecture adheres strictly to the following 5 Laws:

### 1. Input is Toxic
- **Rule:** Never trust `r.Body`, URL parameters, or Headers.
- **Implementation:** All inputs are marshaled into structs with strict validation methods (`Validate()`) before any business logic touches them.
- **Mechanism:** `json.Decoder.DisallowUnknownFields()` is mandatory to prevent payload pollution.

### 2. Silence is Golden
- **Rule:** Never leak internal state or stack traces to the client.
- **Implementation:**
  - **Internal:** Log full stack traces and context to **Sentry** and **Stdout** (structured logging).
  - **External:** Return generic HTTP 500 or 400 errors.
  - **Crypto:** Use `subtle.ConstantTimeCompare` to prevent timing attacks.

### 3. The Database is a Fortress
- **Rule:** SQL Injection is impossible by design; access is strictly scoped.
- **Implementation:**
  - **Type Safety:** We use `sqlc` to generate Go code from SQL, ensuring compiler-checked queries.
  - **No Strings:** String concatenation in SQL is forbidden.
  - **Isolation:** Tenant ID filtering is enforced at the query level.

### 4. Race Conditions are Fatal
- **Rule:** State is shared only when necessary and protected rigorously.
- **Implementation:** Handlers are stateless. Shared resources (like connection pools) are initialized once. usage of `sync.Mutex` or Channels is required for any mutable shared state.

### 5. Dependency Paranoia
- **Rule:** Minimal, trusted dependencies only.
- **Implementation:** We stick to the standard library, `golang.org/x/*`, and battle-tested giants (`chi`, `pgx`, `sentry-go`). No "flavor of the month" packages.

---

## 🏗️ System Components

### 1. HTTP Layer (`internal/api`)
- **Router:** `go-chi/chi` v5. chosen for lightweight, idiomatic routing.
- **Middleware:**
  - **Sentry:** Captures panics and performance traces.
  - **Logger:** Custom `slog` middleware for structured request logging.
  - **PanicRecovery:** Custom middleware with Sentry integration and safe error responses.
- **Handlers:** Stateless functions that parse input -> call service -> render response.

### 2. Domain Logic (`internal/auth`)
- **Service Layer:** Modularized domain services (`login_service.go`, `registration_service.go`, etc.) containing business rules.
- **Dependencies:** Injected via interfaces or pointers (`*db.Queries`, `Hasher`, `TokenProvider`).
- **Cryptography:**
  - **Hashing:** Bcrypt with calibrated cost.
  - **Tokens**: JWT with strictly enforced expiration and issuer validation.

### 3. Storage Layer (`internal/storage`)
- **Driver:** `pgx`/v5 for high-performance PostgreSQL interaction.
- **ORM-lite:** `sqlc` generates type-safe Go structs.
- **Migrations:** Managed via SQL files to ensure schema version control.

### 4. Active Defense (`internal/api/middleware`)
- **Rate Limiting:** Token bucket algorithm (25 req/s, burst 50) protects against brute force while allowing dashboard usage.
- **Tenant Isolation:** `TenantContext` middleware enforces `X-Tenant-ID` and tags telemetry.
- **Strict Headers:** Requests without `Content-Type: application/json` are rejected immediately.

### 5. Compliance & Audit (`internal/audit`)
- **Audit Logger:** Immutable structured logging for business-critical events.
- **Data Hygiene Worker:** Background service (`cmd/worker`) running hourly ticks to purge expired tokens (GDPR/Compliance).

### 6. Access Control (`internal/api/middleware/rbac.go`)
- **Role Enforcement:** Middleware validates role from Context (Claims-based) without DB connection. 0ms latency.

---

## 📂 Directory Structure

```text
.
├── cmd/
│   ├── api/                # Main HTTP API Entry point.
│   ├── control/            # Operator CLI for tenant management.
│   ├── emailworker/        # Email delivery worker.
│   ├── keygen/             # Utility for generating keys.
│   ├── migrate/            # Database migration tool.
│   └── worker/             # Background Janitor service.
├── internal/
│   ├── api/                # HTTP Handlers, Router, Middleware.
│   ├── auth/               # Core business logic. Modular services (Login, Register, MFA, etc).
│   ├── domain/             # Shared domain models/structs.
│   └── storage/
│       ├── db/             # Generated sqlc code (DO NOT EDIT).
│       └── queries/        # Raw SQL queries used by sqlc.
├── pkg/
│   └── logger/             # Public utility packages (structured logging).
├── migrations/             # Database schema migrations.
└── docs/                   # YOU ARE HERE.
```
