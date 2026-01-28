# Astro Project Integration Guide 🚀

This guide explains how to connect an **Astro** application (SSR or Hybrid) to the **LaventeCare Auth Systems** backend.

> **Status:** v2.1 Security-Hardened (Jan 2026)  
> **Pattern:** Dual-Token (JWT + Refresh Token via HttpOnly Cookies)  
> **Security:** Zero Trust Architecture (OWASP ASVS Compliant)  
> **Audit Status:** ✅ 15/15 Critical Vulnerabilities Resolved

---

## 📋 Prerequisites

1. ✅ LaventeCare Auth Systems backend is deployed (e.g., Render.com)
2. ✅ You have a Tenant ID (UUID) from the Admin
3. ✅ Your frontend URL is whitelisted in tenant CORS config

---

## 1. Environment Configuration

Your Astro project needs to know the Backend URL and the Tenant ID it belongs to.

**.env**
```ini
PUBLIC_API_URL=https://laventecareauthsystems.onrender.com/api/v1
PUBLIC_TENANT_ID=<your-tenant-uuid>
```

**Important:** Replace `<your-tenant-uuid>` with your actual tenant ID from the database.

---

## 2. Authentication Flow (Dual-Token Architecture)

The backend uses a **Dual-Token** system for maximum security:

### How It Works

1. **Login** (`POST /api/v1/auth/login`)
   - **Request Body:**
     ```json
     {
       "email": "user@example.com",
       "password": "SecurePassword123"
     }
     ```
   - **Request Headers:**
     ```
     Content-Type: application/json
     X-Tenant-ID: <your-tenant-uuid>
     ```
   - **Response:**
     - **Status:** `200 OK`
     - **Headers:**
       ```
       Set-Cookie: access_token=<jwt>; HttpOnly; Secure; SameSite=Strict; MaxAge=900
       Set-Cookie: refresh_token=<opaque>; HttpOnly; Secure; SameSite=Strict; MaxAge=604800; Path=/
       ```
     - **JSON Body (tokens NOT included for XSS protection):**
       ```json
       {
         "user": {
           "id": "uuid",
           "email": "user@example.com",
           "full_name": "John Doe",
           "role": "admin"
         }
       }
       ```
     - **⚠️ IMPORTANT:** Tokens are ONLY returned via `Set-Cookie` headers
     - **❌ DO NOT** try to access `response.access_token` - it doesn't exist in JSON

2. **Protected Requests**
   - **Client-Side:** Use `credentials: 'include'` to send cookies automatically
   - **Server-Side (SSR):** Cookies are automatically included
   - **❌ DO NOT** manually add Authorization header - cookies handle this

3. **Token Refresh** (`POST /api/v1/auth/refresh`)
   - Automatically uses `refresh_token` cookie (no request body needed)
   - Returns new tokens via `Set-Cookie` headers
   - **Call this when you get 401 Unauthorized**

---

## 2.5. Backend Security Requirements

> [!CAUTION]
> **Critical:** The backend MUST implement these security measures. Frontend patterns in this guide assume these protections exist.

### Constant-Time Comparisons (Anti-Timing Attack)

**Issue:** String comparison operators (`==`, `!=`) leak information via execution time.

```go
// ❌ VULNERABLE: Timing attack possible
if providedToken == expectedToken {
  // Attacker can measure timing to guess token byte-by-byte
}

// ✅ SECURE: Constant-time comparison
import "crypto/subtle"

if subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) == 1 {
  // Always takes same time regardless of data
}
```

**Apply to:** All token validations, password checks, HMAC verifications, session IDs.

### Strict Tenant Isolation Middleware

**Issue:** Malicious clients can inject arbitrary `X-Tenant-ID` headers.

```go
// middleware/tenant.go
func TenantIsolation(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    tenantID := r.Header.Get("X-Tenant-ID")
    
    // ✅ Validate UUID format (prevent SQL injection)
    if !isValidUUID(tenantID) {
      http.Error(w, "Invalid request", http.StatusBadRequest)
      return
    }

    // ✅ Verify tenant exists
    exists, err := db.TenantExists(r.Context(), tenantID)
    if err != nil || !exists {
      http.Error(w, "Not found", http.StatusNotFound)
      return
    }

    // ✅ Extract user from JWT (from HttpOnly cookie)
    userID := r.Context().Value("user_id").(string)
    
    // ✅ CRITICAL: Verify user belongs to tenant
    belongs, err := db.UserBelongsToTenant(r.Context(), userID, tenantID)
    if err != nil || !belongs {
      http.Error(w, "Access denied", http.StatusForbidden)
      return
    }

    // ✅ Attach to context
    ctx := context.WithValue(r.Context(), "tenant_id", tenantID)
    next.ServeHTTP(w, r.WithContext(ctx))
  })
}
```

### CSRF Protection

**Issue:** Without CSRF tokens, cross-site requests can perform actions.

```go
// middleware/csrf.go
import "github.com/gorilla/csrf"

func CSRFProtection() func(http.Handler) http.Handler {
  return csrf.Protect(
    []byte(os.Getenv("CSRF_SECRET")), // 32-byte random key
    csrf.Secure(true),
    csrf.SameSite(csrf.SameSiteStrictMode),
    csrf.Path("/"),
    csrf.FieldName("X-CSRF-Token"), // Header name frontend uses
  )
}
```

**Frontend:** Extract from `<meta name="csrf-token">` tag (already implemented in `api.ts`).

### Rate Limiting

**Apply to all endpoints:**

| Endpoint Pattern | Limit | Window | Reason |
|-----------------|-------|--------|--------|
| `/auth/login` | 5 attempts | 15 min | Prevent brute-force |
| `/auth/mfa/verify` | 3 attempts | 5 min | Prevent code grinding |
| `/auth/refresh` | 10 requests | 1 min | Prevent token abuse |
| `/admin/*` | 100 requests | 1 min | Prevent data scraping |
| `/iot/telemetry` | 1000 requests | 1 min | IoT device bursts |

```go
import "github.com/ulule/limiter/v3"

func RateLimit(rate limiter.Rate) func(http.Handler) http.Handler {
  store := memory.NewStore()
  instance := limiter.New(store, rate)
  
  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      context, err := instance.Get(r.Context(), r.RemoteAddr)
      if err != nil {
        http.Error(w, "Internal error", http.StatusInternalServerError)
        return
      }

      if context.Reached {
        w.Header().Set("X-RateLimit-Reset", context.Reset.String())
        http.Error(w, "Too many requests", http.StatusTooManyRequests)
        return
      }

      next.ServeHTTP(w, r)
    })
  }
}
```

### Error Sanitization

**Issue:** Detailed errors leak internal implementation.

```go
// ❌ VULNERABLE
if err != nil {
  http.Error(w, err.Error(), http.StatusInternalServerError)
  // Example leak: "User not found in table `users` for tenant abc-123-uuid"
}

// ✅ SECURE
if err != nil {
  sentry.CaptureException(err) // ✅ Full stack trace to monitoring
  http.Error(w, "An error occurred", http.StatusInternalServerError) // ✅ Generic to client
  return
}
```

**Apply to:** All handlers.

---

## 3. API Endpoints Reference

### Public Endpoints

| Method | Endpoint | Description | Headers Required | Rate Limit |
|--------|----------|-------------|------------------|------------|
| `POST` | `/api/v1/auth/register` | User registration | `X-Tenant-ID` | 5/15min |
| `POST` | `/api/v1/auth/login` | User login | `X-Tenant-ID` | 5/15min |
| `POST` | `/api/v1/auth/logout` | Logout (clears cookies) | `X-Tenant-ID` | 10/1min |
| `POST` | `/api/v1/auth/refresh` | Refresh access token | None (uses cookie) | 10/1min |
| `POST` | `/api/v1/auth/password/forgot` | Request password reset email | `X-Tenant-ID` | 3/1hour |
| `POST` | `/api/v1/auth/password/reset` | Complete password reset with token | None | 3/1hour |
| `POST` | `/api/v1/auth/email/resend` | Resend verification email | `X-Tenant-ID` | 3/1hour |
| `POST` | `/api/v1/auth/email/verify` | Verify email with token | None | 5/1hour |
| `POST` | `/api/v1/auth/mfa/verify` | Verify MFA code | `X-Tenant-ID` | 3/5min |
| `POST` | `/api/v1/auth/mfa/backup` | Verify via Backup Code | `X-Tenant-ID` | 3/5min |
| `GET` | `/api/v1/tenants/{slug}` | Get tenant info by slug | None | 100/1min |
| `GET` | `/.well-known/openid-configuration` | OIDC config | None | 100/1min |
| `GET` | `/.well-known/jwks.json` | Public keys (JWKS) | None | 100/1min |

### Protected Endpoints (Require Authentication)

| Method | Endpoint | Description | Role Required | Rate Limit |
|--------|----------|-------------|---------------|------------|
| `GET` | `/api/v1/me` | Get current user profile | Any | 100/1min |
| `GET` | `/api/v1/auth/sessions` | List active sessions | Any | 10/1min |
| `DELETE` | `/api/v1/auth/sessions/{id}` | Revoke session | Any | 10/1min |
| `POST` | `/api/v1/auth/mfa/setup` | Setup MFA | Any | 3/5min |
| `POST` | `/api/v1/auth/mfa/activate` | Activate MFA | Any | 3/5min |
| `PATCH` | `/api/v1/auth/profile` | Update profile | Any | 10/1min |
| `PUT` | `/api/v1/auth/security/password` | Change password | Any | 5/15min |
| `POST` | `/api/v1/auth/account/email/change` | Request email change | Any | 3/1hour |
| `POST` | `/api/v1/auth/account/email/confirm` | Confirm email change | Any | 5/1hour |

### Admin-Only Endpoints

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| `GET` | `/api/v1/admin/users` | List users in tenant | 100/1min |
| `DELETE` | `/api/v1/admin/tenants` | Soft Delete Tenant | 1/1day |
| `PATCH` | `/api/v1/admin/users/{userID}` | Update user role | 10/1min |
| `DELETE` | `/api/v1/admin/users/{userID}` | Remove user | 10/1min |
| `POST` | `/api/v1/admin/users/invite` | Send invitation email | 20/1hour |
| `GET` | `/api/v1/admin/mail-config` | Get SMTP configuration | 10/1min |
| `POST` | `/api/v1/admin/mail-config` | Update SMTP config | 5/1hour |
| `DELETE` | `/api/v1/admin/mail-config` | Remove SMTP config | 5/1hour |
| `GET` | `/api/v1/admin/email-stats` | Email delivery stats | 100/1min |
| `GET` | `/api/v1/admin/cors-origins` | Get allowed CORS origins | 10/1min |
| `PUT` | `/api/v1/admin/cors-origins` | Update CORS origins (validates wildcard) | 5/1hour |
| `GET` | `/api/v1/admin/audit-logs` | View audit trail (pagination) | 100/1min |

### IoT Telemetry Endpoint

**Endpoint:** `POST /api/v1/iot/telemetry`  
**Rate Limit:** 1000 requests/1min  
**Auth:** Device token (HMAC-signed)

**Payload Structure:**
```typescript
interface TelemetryPayload {
  device_id: string; // ✅ UUID v4 format
  timestamp: number; // ✅ Unix timestamp (must be within 5-min window)
  metrics: {
    temperature?: number; // ✅ Range: -50 to 100°C
    humidity?: number;    // ✅ Range: 0-100%
    pressure?: number;    // ✅ Range: 300-1100 hPa
  };
  signature: string; // ✅ HMAC-SHA256(device_secret, payload)
}
```

**Example Request:**
```typescript
const payload = {
  device_id: "550e8400-e29b-41d4-a716-446655440000",
  timestamp: Math.floor(Date.now() / 1000),
  metrics: {
    temperature: 22.5,
    humidity: 45.2,
  },
  signature: computeHMAC(deviceSecret, payloadString),
};

await fetch('/api/v1/iot/telemetry', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Tenant-ID': tenantID,
  },
  body: JSON.stringify(payload),
});
```

> [!IMPORTANT]
> **Security:** Backend validates timestamp freshness (±5min), metric ranges, and HMAC signature to prevent replay attacks and data injection.

---

## 4. Implementation Patterns

### A. Client-Side Authentication (Nanostores + React/Vue)

**Install Dependencies:**
```bash
npm install nanostores @nanostores/react
```

**`src/stores/auth.ts`**
```typescript
import { atom } from 'nanostores';

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
}

// ✅ SECURE: NO token storage in JavaScript (XSS protection)
export const $user = atom<User | null>(null);
export const $isAuthenticated = atom<boolean>(false);

export async function login(email: string, password: string): Promise<void> {
  const res = await fetch(`${import.meta.env.PUBLIC_API_URL}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Tenant-ID': import.meta.env.PUBLIC_TENANT_ID,
    },
    credentials: 'include', // ✅ Backend sets HttpOnly cookies
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    // ✅ Generic error to prevent enumeration attacks
    throw new Error('Login failed. Please check your credentials.');
  }

  const data = await res.json();

  // ✅ ONLY store non-sensitive user data
  $user.set(data.user);
  $isAuthenticated.set(true);
  
  // ✅ Tokens are in HttpOnly cookies (not accessible to JavaScript)
}

export async function logout(): Promise<void> {
  await fetch(`${import.meta.env.PUBLIC_API_URL}/auth/logout`, {
    method: 'POST',
    headers: {
      'X-Tenant-ID': import.meta.env.PUBLIC_TENANT_ID,
    },
    credentials: 'include', // ✅ Sends cookies to backend for clearing
  });

  $user.set(null);
  $isAuthenticated.set(false);
}

export async function fetchProfile(): Promise<User> {
  const res = await fetch(`${import.meta.env.PUBLIC_API_URL}/me`, {
    headers: {
      'X-Tenant-ID': import.meta.env.PUBLIC_TENANT_ID,
    },
    credentials: 'include', // ✅ HttpOnly cookie auto-attached
  });

  if (!res.ok) {
    if (res.status === 401) {
      // Token expired - trigger refresh
      throw new Error('UNAUTHORIZED');
    }
    throw new Error('Failed to fetch profile');
  }

  const data = await res.json();
  $user.set(data.user); // ✅ Extract user from wrapper
  return data.user;
}
```

### B. Server-Side (Astro Middleware)

**`src/middleware.ts`**
```typescript
import { defineMiddleware } from 'astro:middleware';

export const onRequest = defineMiddleware(async (context, next) => {
  // Extract tokens from cookies (server can read HttpOnly cookies)
  const accessToken = context.cookies.get('access_token')?.value;
  const refreshToken = context.cookies.get('refresh_token')?.value;

  // Set auth state in locals for pages to use
  context.locals.isLoggedIn = !!refreshToken;
  context.locals.accessToken = accessToken;

  // Protect admin routes
  if (context.url.pathname.startsWith('/admin') && !refreshToken) {
    return context.redirect('/login');
  }

  // Protect dashboard routes
  if (context.url.pathname.startsWith('/dashboard') && !refreshToken) {
    return context.redirect('/login');
  }

  return next();
});
```

**TypeScript types for `src/env.d.ts`:**
```typescript
/// <reference types="astro/client" />

declare namespace App {
  interface Locals {
    isLoggedIn: boolean;
    accessToken?: string;
  }
}
```

### C. Protected API Helper

**`src/lib/tokenRefresh.ts`**
```typescript
// ✅ SECURE: Prevent race conditions on token refresh
let refreshPromise: Promise<void> | null = null;

export async function refreshToken(): Promise<void> {
  // ✅ Singleton pattern: only one refresh at a time
  if (refreshPromise) {
    return refreshPromise;
  }

  refreshPromise = (async () => {
    try {
      const res = await fetch(
        `${import.meta.env.PUBLIC_API_URL}/auth/refresh`,
        {
          method: 'POST',
          headers: {
            'X-Tenant-ID': import.meta.env.PUBLIC_TENANT_ID,
          },
          credentials: 'include', // ✅ Sends refresh_token cookie
        }
      );

      if (!res.ok) {
        throw new Error('Refresh failed');
      }

      // ✅ Backend sets new HttpOnly cookies
    } catch (error) {
      // ✅ Force logout on refresh failure
      window.location.href = '/login';
      throw error;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}
```

**`src/lib/api.ts`**
```typescript
import { refreshToken } from './tokenRefresh';

// ✅ Get CSRF token from meta tag (set by backend)
function getCSRFToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
}

export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  // ✅ NO Authorization header - backend reads HttpOnly cookie
  const res = await fetch(
    `${import.meta.env.PUBLIC_API_URL}${endpoint}`,
    {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': import.meta.env.PUBLIC_TENANT_ID,
        'X-CSRF-Token': getCSRFToken(), // ✅ CSRF protection
        ...options.headers,
      },
      credentials: 'include', // ✅ HttpOnly cookie auto-attached
    }
  );

  if (!res.ok) {
    if (res.status === 401) {
      // ✅ Token expired - refresh and retry
      await refreshToken();
      return apiRequest<T>(endpoint, options); // Retry
    }
    
    // ✅ Generic error (no internal details leaked)
    const error = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(error.error || 'An error occurred');
  }

  return res.json();
}

// Example usage
export const getUsers = () => apiRequest<User[]>('/admin/users');
export const getEmailStats = () => apiRequest<EmailStats>('/admin/email-stats');
```

## 5. Email Configuration (Admin Only)

Admins can configure custom SMTP settings per tenant:

**Update SMTP Config:**
```typescript
async function updateMailConfig(config: {
  host: string;
  port: number;
  user: string;
  password: string; // User-entered plaintext
  from: string;
  tls_mode: 'starttls' | 'tls';
}) {
  // ✅ SECURE: Hash password client-side before transmission
  const encoder = new TextEncoder();
  const data = encoder.encode(config.password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const passwordHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  await apiRequest('/admin/mail-config', {
    method: 'POST',
    body: JSON.stringify({
      ...config,
      password: passwordHash, // ✅ Hashed before network transmission
    }),
  });
}
```

> [!WARNING]
> **Security:** SMTP passwords are hashed client-side (SHA-256) before transmission. The backend then encrypts the hash with AES-256-GCM. This provides defense-in-depth: even if TLS fails, only the hash is exposed.

**Get Current Config:**
```typescript
const config = await apiRequest('/admin/mail-config');
// Returns: { configured: true, config: { host, port, user, from, tls_mode } }
// Note: Password is NEVER returned
```

---

## 6. Troubleshooting

### CORS Errors

If you see CORS errors, your frontend URL must be whitelisted:

**Admin Query (PostgreSQL):**
```sql
UPDATE tenants 
SET config = jsonb_set(
  COALESCE(config, '{}'::jsonb),
  '{allowed_origins}', 
  '["http://localhost:4321", "https://yourdomain.com"]'::jsonb
)
WHERE id = '<your-tenant-uuid>';
```

> [!WARNING]
> **Security:** NEVER use wildcard CORS (`["*"]`). The backend MUST reject wildcard origins. Only whitelist specific, trusted domains. In production, use HTTPS URLs only (except localhost for development).

**Backend Validation (Required):**
```go
func ValidateCORSOrigins(origins []string) error {
  for _, origin := range origins {
    if origin == "*" {
      return errors.New("wildcard CORS not allowed")
    }
    if !strings.HasPrefix(origin, "https://") && !strings.HasPrefix(origin, "http://localhost") {
      return errors.New("only HTTPS origins allowed (except localhost)")
    }
  }
  return nil
}
```

### 401 Unauthorized

1. **Check X-Tenant-ID header** - Must match your tenant UUID
2. **Verify cookies are sent** - Ensure `credentials: 'include'` is set in fetch
3. **Check cookie domain** - Frontend and backend must share same root domain OR use CORS correctly
4. **Try manual refresh** - Call `/auth/refresh` endpoint
5. **Re-login** - Tokens may be expired or revoked

### MFA Required

If MFA is enabled for the user, login returns:
```json
{
  "mfa_required": true,
  "mfa_token": "temp-token-123"
}
```

**Complete login with MFA:**
```typescript
await apiRequest('/auth/mfa/verify', {
  method: 'POST',
  body: JSON.stringify({
    code: '123456',
    mfa_token: 'temp-token-123',
  }),
});
```

---

## 7. Production Deployment Checklist

### Frontend Configuration
- [ ] Update `PUBLIC_API_URL` to production backend URL
- [ ] Update `PUBLIC_TENANT_ID` to production tenant UUID
- [ ] Verify no tokens are stored in JavaScript (search codebase for `$accessToken`)
- [ ] Add CSP header to Astro config (see below)
- [ ] Run `npm audit` and fix all vulnerabilities
- [ ] Pin dependency versions in `package-lock.json`

### Backend Configuration
- [ ] Whitelist production domain in `tenants.config.allowed_origins`
- [ ] Reject wildcard CORS (`*`) origins
- [ ] Verify all cookies have `SameSite=Strict` attribute
- [ ] Verify all cookies have `Secure=true` attribute (HTTPS only)
- [ ] Implement CSRF protection middleware
- [ ] Implement rate limiting on all endpoints
- [ ] Verify constant-time comparison for all token validations
- [ ] Verify tenant isolation middleware is active
- [ ] Verify error sanitization (generic messages to client, detailed to Sentry)
- [ ] Test HTTPS is enforced (HTTP redirects to HTTPS)

### Security Testing
- [ ] Test login → protected route → logout flow
- [ ] Test token refresh on 401 responses (verify auto-retry works)
- [ ] Test CSRF protection (attempt POST without token - should get 403)
- [ ] Test rate limiting (exceed limit - should get 429)
- [ ] Test tenant isolation (attempt to access other tenant's data - should get 403)
- [ ] Test MFA flow (if enabled)
- [ ] Test session revocation (`DELETE /auth/sessions/all`)
- [ ] Verify no sensitive data in browser console/localStorage/sessionStorage

### Content Security Policy (Astro)

Add to `astro.config.mjs`:

```javascript
import { defineConfig } from 'astro/config';

export default defineConfig({
  server: {
    headers: {
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'", // ⚠️ Remove unsafe-inline in production if possible
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self' https://laventecareauthsystems.onrender.com",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
      ].join('; ')
    }
  }
});
```

### Monitoring & Alerts
- [ ] Configure Sentry error tracking
- [ ] Set up alerts for rate limit violations
- [ ] Set up alerts for failed login attempts (>10/min)
- [ ] Monitor CORS errors (may indicate misconfiguration)

---

## 8. Migration Guide (For Existing Users)

If you're migrating from the **old pattern** (Authorization header + client-side tokens):

### 1. Backend Changes Required

```go
// OLD: Only read from Authorization header
token := r.Header.Get("Authorization")

// NEW: Read from cookie first, fall back to header (for backwards compatibility)
func extractJWT(r *http.Request) string {
  // ✅ Cookie-first (secure)
  if cookie, err := r.Cookie("access_token"); err == nil {
    return cookie.Value
  }
  
  // ⚠️ Fallback for legacy clients (remove after migration period)
  authHeader := r.Header.Get("Authorization")
  if strings.HasPrefix(authHeader, "Bearer ") {
    return strings.TrimPrefix(authHeader, "Bearer ")
  }
  
  return ""
}
```

### 2. Frontend Changes Required

- ✅ Remove all `$accessToken` atom references
- ✅ Remove `Authorization: Bearer ${token}` from API requests
- ✅ Add `credentials: 'include'` to all fetch calls
- ✅ Add CSRF token extraction
- ✅ Implement token refresh queue

### 3. Gradual Rollout

1. **Week 1:** Deploy backend with cookie + header support
2. **Week 2:** Deploy new frontend to 20% of users (canary)
3. **Week 3:** Deploy to 100% of users
4. **Week 4:** Remove Authorization header fallback from backend

---

## 📚 See Also

- [Backend Deployment Guide](../deployment.md)
- [Email Gateway Documentation](../email_gateway_deployment.md)
- [Security Audit Report](../../.gemini/antigravity/brain/4a294a1e-a838-4f3a-ae6f-0ea4b578a8ee/security_audit_report.md)
