# API Reference & Conventions

## 📡 Protocol Standards
Calls are made via HTTP/1.1 or HTTP/2 over TLS (in production).

- **Base URL**: `/api/v1`
- **Content-Type**: `application/json` is mandatory for request bodies.

---

## 📝 Request Handling

### Validation ("Anti-Gravity Law 1")
Every handler implements strict validation before processing logic.
- **Pattern**: `req.Validate()` method on input structs.
- **Strict Decoding**: `json.NewDecoder(r.Body).DisallowUnknownFields()`.

### Header Requirements
| Header | Value | Required | Description |
| :--- | :--- | :--- | :--- |
| `Content-Type` | `application/json` | Yes | For POST/PUT |
| `Authorization` | `Bearer <token>` | Yes | For protected routes |
| `X-Tenant-ID` | `<uuid>` | Optional | To switch context explicitly |

---

## 🚦 Response Format

### Login Response
Standard HTTP 200.
```json
{
  "access_token": "eyJhbGciOiJIUzI1Ni...",
  "refresh_token": "...",
  "user": {
      "id": "...",
      "email": "..."
  },
  "mfa_required": false
}
```
*Note: If `mfa_required` is true, tokens will be empty/null.*

### Errors ("Anti-Gravity Law 2")
We return standard HTTP status codes. The body is typically **plain text** to keep it simple and minimizes parsing risks on client-side for fatal errors.

```text
Invalid request parameters
```

| Status | Meaning | Usage |
| :--- | :--- | :--- |
| `400` | Bad Request | Validation failure, Broken JSON, **Missing Content-Type**. |
| `401` | Unauthorized | Missing/Invalid Token, Login Failed. |
| `403` | Forbidden | Valid Token, but insufficient permissions. |
| `404` | Not Found | Resource does not exist (or hidden). |
| `415` | Unsupported Media Type | Sent anything other than `application/json`. |
| `429` | Too Many Requests | Rate limit exceeded (**25 req/s, Burst 50**). |
| `500` | Internal Server Error | Something exploded (Check Sentry). |

---

## 📚 Endpoints & RBAC Requirements

### Discovery & OIDC (Machine-to-Machine)
| Endpoint | Method | Description |
|:---------|:-------|:------------|
| `/.well-known/openid-configuration` | GET | OIDC Discovery Document (for Convex/Auth.js) |
| `/.well-known/jwks.json` | GET | JSON Web Key Set (Public Keys for validation) |

### Public Access & Auth
| Endpoint | Method | Role | Params | Description |

|:---------|:-------|:-----|:-------|:------------|
| `/health` | GET | Public | - | Liveness & DB connectivity check |
| `/auth/register` | POST | Public | `email`, `password`, `full_name` | User registration |
| `/auth/login` | POST | Public | `email`, `password` | Credential validation |
| `/auth/logout` | POST | Public | `refresh_token` (cookie/body) | Revoke token family and logout |
| `/auth/refresh` | POST | Public | `refresh_token` (cookie/body) | Rotate access/refresh tokens |
| `/auth/password/forgot` | POST | Public | `email` | Request password reset link |
| `/auth/password/reset` | POST | Public | `token`, `password` | Complete password reset |
| `/auth/email/verify` | POST | Public | `token` | Verify email address |
| `/auth/email/resend` | POST | Public | `email` | Resend verification email |
| `/auth/mfa/verify` | POST | Public | `totp_code`, `session_token` | Complete MFA login |
| `/auth/mfa/backup` | POST | Public | `backup_code`, `session_token` | Complete MFA via backup code |
| `/tenants/{slug}` | GET | Public | - | Retrieve tenant public metadata |
| `/showcase` | GET | Public | - | **List featured tenants** (Rich Metadata: Tagline, Screenshots, Socials) |

### User Self-Service (Protected)
*Requires `Authorization: Bearer <token>`*

| Endpoint | Method | Role | Description |
|:---------|:-------|:-----|:------------|
| `/auth/me` | GET | Viewer+ | Get current user's profile |
| `/auth/token` | GET | Viewer+ | Get token for integrations (e.g. Convex) |
| `/auth/profile` | PATCH | Viewer+ | Update own profile details |
| `/auth/security/password` | PUT | Viewer+ | Change password |
| `/auth/sessions` | GET | Viewer+ | List active sessions |
| `/auth/sessions/{id}` | DELETE | Viewer+ | Revoke specific session |
| `/auth/mfa/setup` | POST | Viewer+ | Initiate MFA enrollment (returns QR) |
| `/auth/mfa/activate` | POST | Viewer+ | Confirm MFA enrollment |
| `/auth/account/email/change` | POST | Viewer+ | Request email change |
| `/auth/account/email/confirm` | POST | Viewer+ | Confirm email change |

### Tenant Administration (Admin Only)
*Requires `Authorization: Bearer <token>` and `Role: admin`*

| Endpoint | Method | Description |
|:---------|:-------|:------------|
| `/admin/users` | GET | List users in tenant |
| `/admin/users/invite` | POST | Invite new member to tenant |
| `/admin/users/{userID}` | PATCH | Update member role |
| `/admin/users/{userID}` | DELETE | Remove member from tenant |

| `/admin/tenants` | POST | `name`, `slug`, `app_url` | **Create new tenant** (Audit Form) |
| `/admin/tenants` | DELETE | - | **Danger**: Delete the current tenant context |
| `/admin/audit-logs` | GET | View security audit logs |

### Email Gateway Configuration (Admin Only)
*Control external SMTP settings for the tenant*

| Endpoint | Method | Payload | Description |
|:---------|:-------|:--------|:------------|
| `/admin/mail-config` | GET | - | Get current SMTP config (sanitized) |
| `/admin/mail-config` | POST | `host`, `port`, `user`, `password`, `from`, `tls_mode` | Set custom SMTP gateway |
| `/admin/mail-config` | DELETE | - | Remove custom SMTP (revert to system default) |
| `/admin/email-stats` | GET | - | View delivery & queue statistics |

### Security Configuration (Admin Only)

| Endpoint | Method | Payload | Description |
|:---------|:-------|:--------|:------------|
| `/admin/cors-origins` | GET | - | Get allowed CORS origins |
| `/admin/cors-origins` | PUT | `allowed_origins` (array) | Update allowed CORS origins |

### IoT Gateway (ESP32 / Embedded)
*Dedicated low-overhead endpoints for hardware telemetry.*

| Endpoint | Method | Headers | Payload | Description |
|:---------|:-------|:--------|:--------|:------------|
| `/iot/telemetry` | POST | `X-ESP32-Secret` | `sensor_id`, `timestamp`, `data` (json) | Ingest sensor data & proxy to Convex |

---

**Role Hierarchy:** `admin` > `editor` > `viewer`
**Permission Model:** A user with `admin` role can access all `editor` and `viewer` endpoints. `editor` can access `viewer` endpoints.
