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
