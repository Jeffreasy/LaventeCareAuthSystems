# Test Strategy

## 🛡️ Anti-Gravity Testing Protocol
Testing is not an afterthought; it is the proof of stability.

### 1. Layers
- **Unit Tests (`_test.go`)**: 
    - **Scope**: Service layer logic, Crypto utilities, Validation helpers.
    - **Mocking**: Use interfaces (`PasswordHasher`, `TokenProvider`, `EmailSender`) to mock external dependencies.
    - **Goal**: 100% coverage of business rules path.

- **Integration Tests**:
    - **Scope**: Database queries and API Endpoints.
    - **Infrastructure**: Use `testcontainers-go` or a dedicated Docker `db_test` service.
    - **Goal**: Verify SQL queries against real Postgres and HTTP Handlers against real router.

### 2. Tools
- **Framework**: Standard `testing` package.
- **Assertions**: `github.com/stretchr/testify/assert`.
- **Mocks**: `github.com/stretchr/testify/mock` or manual mocks (preferred for simplicity).

### 3. CI/CD Enforcements
- **Linting**: `golangci-lint` (Strict configuration).
- **Security Scan**: `govulncheck`.
- **Race Detection**: `go test -race ./...`.

---

## 🎯 Core Domain Test Coverage

To guarantee the 4 foundational security domains remain intact, the following test categories are **mandatory**:

### 1. Identiteitsbeheer (Identity Management)
- **Password Hashing**: Verify Bcrypt cost is 12, rejection of weak passwords (<12 chars).
- **JWT Validation**: Test token expiration, invalid signatures, audience/issuer mismatch.
- **Token Rotation**: Verify refresh token family rotation and reuse detection (anti-replay).
- **MFA Flows**: Test TOTP generation/validation, backup code one-time-use, invalid code rejection.
- **Verification Tokens**: Test email verification \u0026 password reset flows, expiration enforcement.

**Example Test:**
```go
func TestRefreshTokenReuse_ShouldRevokeFamily(t *testing.T) {
    // Use a rotated refresh token twice → Expect entire family revoked
}
```

### 2. Strict Isolation (Multi-Tenancy)
- **IDOR Prevention**: Attempt to access resources from Tenant A using credentials from Tenant B → Expect 403/404.
- **Query Scoping**: Verify all database queries include `tenant_id` WHERE clause (static analysis or integration test).
- **Session Isolation**: Verify sessions created in Tenant A cannot be used in Tenant B context.

**Example Test:**
```go
func TestCrosstenantAccess_ShouldFail(t *testing.T) {
    // User from tenant_1 tries to GET /api/v1/tenants/tenant_2/resources/xyz
    // Expected: 403 Forbidden or 404 Not Found (no leak of existence)
}
```

### 3. Toegangscontrole (RBAC)
- **Role Enforcement**: Verify `viewer` cannot access `admin`-only endpoints → Expect 403.
- **Role Hierarchy**: Test that `admin` can access `editor` and `viewer` endpoints.
- **Tampered Claims**: Test JWT with manually edited `role` claim → Expect signature validation failure.

**Example Test:**
```go
func TestRBACMiddleware_ViewerAccessAdminEndpoint_ShouldFail(t *testing.T) {
    // Token with role="viewer" attempts POST /api/v1/admin/users/invite
    // Expected: 403 Forbidden
}
```

### 4. Integriteit \u0026 Verantwoording (Audit Logging)
- **Immutability**: Verify UPDATE/DELETE on `audit_logs` table is blocked at DB level.
- **Capture Completeness**: Verify critical actions (login, logout, user creation, role change) generate audit log entries.
- **Tenant Scoping**: Verify audit logs respect tenant isolation (Tenant A cannot query Tenant B's logs).

**Example Test:**
```go
func TestAuditLog_ImmutabilityEnforcement(t *testing.T) {
    // Insert audit log → Attempt UPDATE/DELETE → Expect PostgreSQL permission error
}
```

---

## 🔬 Running Tests

```bash
# Run all tests with race detector
go test -race ./...

# Run with coverage report
go test -cover -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Security vulnerability scan
govulncheck ./...
```
