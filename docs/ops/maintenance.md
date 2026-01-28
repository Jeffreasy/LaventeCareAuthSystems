# Operations & Best Practices

## ⚙️ Running in Production

### Telemetry & Observability
We use **Sentry** for error tracking and performance monitoring.

- **Initialization**: Automatic if `SENTRY_DSN` env var is present.
- **Traces**: Currently sampled at 1.0 (100%) for Development. Adjust `TracesSampleRate` in `main.go` for Production.
- **Context**: Standard environment tags. (Advanced user context enrichment is currently stubbed/disabled in `internal/api/middleware/sentry.go`).

### Logging
Structured logging via Go 1.21+ `log/slog`.

- **Format**: JSON (Production) or Text (Development).
- **Levels**:
    - `INFO`: Business events (Startup, Login Success).
    - `WARN`: User errors (Validation, 401s).
    - `ERROR`: System failures (DB down, Panic).

**Note:** Never log sensitive data (passwords, tokens, PII) in the log message or attributes.

### Disaster Recovery
See [Disaster Recovery Runbooks](disaster_recovery.md) for Backup, Restore, and Secret Rotation procedures.

---

## 🚀 Deployment Checklist

### Audit Logging
We maintain a strict **Business Audit Log** (`EventDataAccess`, `EventLoginSuccess`) separate from technical logs.
- **Format**: JSON structured fields.
- **Key Fields**: `log_type="AUDIT_TRAIL"`, `actor_id`, `action`, `resource`.
- **Destination**: Standard Output (aggregated to secure index like Splunk/Datadog).

---

## 🚀 Deployment Checklist

Before going live, verify the following:

1.  [ ] **Environment**: `APP_ENV=production`.
2.  [ ] **Secrets**: `JWT_SECRET` is strong (min 32 chars) and unique.
3.  [ ] **Database**: `sslmode=require` in `DATABASE_URL`.
4.  [ ] **Rate Limits**: Adjusted for production load (default 5 RPS may be too low for NATs).
5.  [ ] **Sentry**: DSN is configured.
6.  [ ] **Migrations**: Database schema is up to date.

---

## 🛡️ "How To" Guides

### How to Add a Secure Endpoint
1.  **Define Route**: Add to `router.go`.
2.  **Define Request Struct**: Create struct in `handlers.go` with JSON tags.
3.  **Implement Validation**: Add `Validate()` method to struct.
4.  **Handler Logic**:
    - Decode with `DisallowUnknownFields()`.
    - Call `req.Validate()`.
    - Call Service logic.
    - Handle error (Log Error -> Return 4xx/500).
