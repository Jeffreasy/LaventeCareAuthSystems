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

## 📚 Endpoints (Brief)

### Public / Semi-Public
- `GET /health`
- `POST /api/v1/auth/register` (Note: May require `invite` token)
- `POST /api/v1/auth/login` (Returns `mfa_required`)
- `POST /api/v1/auth/mfa/verify` (TOTP Login)
- `POST /api/v1/auth/mfa/backup` (Backup Code Login)
- `GET /api/v1/tenants/{slug}`

### Protected (User)
- `POST /api/v1/auth/mfa/setup` (Start Enrollment)
- `POST /api/v1/auth/mfa/activate` (Confirm Enrollment)
- `GET /api/v1/auth/sessions` (List Devices)
- `DELETE /api/v1/auth/sessions/{id}` (Remote Logout)

### Protected (Admin)
- `POST /api/v1/admin/users/invite` (Create Invitation)

### Protected
*Requires `Authorization: Bearer ...`*

*(Endpoints to be documented as they are implemented)*
