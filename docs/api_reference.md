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
| `429` | Too Many Requests | Rate limit exceeded (**5 req/s, Burst 10**). |
| `500` | Internal Server Error | Something exploded (Check Sentry). |

---

---

## 📚 Endpoints \u0026 RBAC Requirements

| Endpoint | Method | Required Role | Auth Header | Description |
|:---------|:-------|:--------------|:------------|:------------|
| `/health` | GET | None (Public) | ❌ | Liveness \u0026 DB connectivity check |
| `/api/v1/auth/register` | POST | None* | ❌ | User registration (*may require invite token) |
| `/api/v1/auth/login` | POST | None | ❌ | Credential validation, returns `mfa_required` flag |
| `/api/v1/auth/mfa/verify` | POST | None | ❌ | TOTP code verification (completes MFA login) |
| `/api/v1/auth/mfa/backup` | POST | None | ❌ | Backup code verification (completes MFA login) |
| `/api/v1/tenants/{slug}` | GET | None (Public) | ❌ | Retrieve tenant public metadata |
| `/api/v1/auth/mfa/setup` | POST | `viewer`+ | ✅ Bearer | Initiate MFA enrollment (returns QR code) |
| `/api/v1/auth/mfa/activate` | POST | `viewer`+ | ✅ Bearer | Confirm MFA enrollment with TOTP code |
| `/api/v1/auth/sessions` | GET | `viewer`+ | ✅ Bearer | List user's active sessions/devices |
| `/api/v1/auth/sessions/{id}` | DELETE | `viewer`+ | ✅ Bearer | Remote logout (revoke specific session) |
| `/api/v1/admin/users/invite` | POST | `admin` | ✅ Bearer | Create tenant invitation for new user |

**Role Hierarchy:** `admin` > `editor` > `viewer`  
**Permission Model:** A user with `admin` role can access all `editor` and `viewer` endpoints. `editor` can access `viewer` endpoints.

*(Endpoints to be documented as they are implemented)*
