# Astro Project Linking Guide 🚀

This guide explains how to connect an **Astro** application (SSR or Hybrid) to the **LaventeCare Auth Systems** backend.

> **Status:** Audited against v1.0 Backend
> **Pattern:** Dual-Token (Header + Cookie)

## 1. Environment Configuration

Your Astro project needs to know the Backend URL and the Tenant ID it belongs to.

**.env**
```ini
PUBLIC_API_URL="https://laventecareauthsystems.onrender.com/api/v1"
PUBLIC_TENANT_ID="<your-tenant-uuid>"
```

## 2. Authentication Flow (The "Ground Truth")

The backend implements a **Dual-Token** architecture designed for maximum security (Anti-Gravity). This affects how your Astro app must handle state.

### How it works
1.  **Login**: Returns specific data formats.
    *   **Response Body (JSON):** Contains `access_token` (JWT) and User Profile.
    *   **Response Cookies:** Sets `refresh_token` (HttpOnly, Secure) and `access_token` (HttpOnly, Secure).
2.  **Access (Requests)**:
    *   **Client-Side:** You MUST modify requests to include `Authorization: Bearer <access_token>`. You **cannot** read the `access_token` cookie via JS.
    *   **Server-Side (SSR):** Astro middleware can read the passed cookies and forward them.
3.  **Refresh**:
    *   Automatic via the `refresh_token` cookie. The endpoint `/auth/refresh` returns a new `access_token` tuple.

---

## 3. Implementation Patterns

### A. Client-Side (Islands / React / Vue)

Since `access_token` cookies are HttpOnly, you must store the Access Token from the JSON response in memory (e.g., Nano Stores) or LocalStorage (less secure but persistent).

**`src/lib/auth.ts`**
```typescript
import { atom } from 'nanostores';

export const $accessToken = atom<string | null>(null);

export async function login(email, password) {
  const res = await fetch(`${import.meta.env.PUBLIC_API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  
  const data = await res.json();
  if (res.ok) {
    // 1. Store Access Token for API calls
    $accessToken.set(data.access_token);
    // 2. Refresh Cookie is set automatically by browser
  }
}
```

### B. Server-Side (Astro Middleware)

For SSR routes, you can proxy the cookies to validate the user session before rendering protected pages.

**`src/middleware.ts`**
```typescript
import { defineMiddleware } from "astro:middleware";

export const onRequest = defineMiddleware(async (context, next) => {
  // 1. Check for specific Access Token cookie (if present)
  // Note: The backend sets 'access_token' cookie, which Astro (server) CAN read.
  const accessToken = context.cookies.get("access_token")?.value;
  const refreshToken = context.cookies.get("refresh_token")?.value;

  // 2. Add to locals for use in pages
  context.locals.isLoggedIn = !!refreshToken;

  // 3. (Optional) Validate User via Backend 'Me' endpoint
  if (context.url.pathname.startsWith("/dashboard") && !refreshToken) {
      return context.redirect("/login");
  }

  return next();
});
```

---

## 4. Protected API Calls (Fetching Data)

When fetching data from the backend, you must handle credentials correctly.

**Example: Fetching Profile**
```typescript
async function fetchProfile() {
    // Use the token from store
    const token = $accessToken.get();

    const res = await fetch(`${import.meta.env.PUBLIC_API_URL}/me`, {
        headers: {
            'Authorization': `Bearer ${token}`, // REQUIRED by Backend Middleware
            'X-Tenant-ID': import.meta.env.PUBLIC_TENANT_ID // REQUIRED for context
        }
    });
    
    // Handle 401 (Token Expired) -> Call Refresh
}
```

## 5. Troubleshooting (CORS)

If you see CORS errors:
1.  The backend enforces **Dynamic Tenant CORS**.
2.  Your Astro URL (e.g., `http://localhost:4321`) MUST be whitelisted in the `tenants` table -> `config` JSON column -> `allowed_origins` array.
3.  Ask an Admin to run:
    ```sql
    UPDATE tenants 
    SET config = jsonb_set(config, '{allowed_origins}', '["http://localhost:4321", "https://myapp.com"]')
    WHERE id = '<your-tenant-uuid>';
    ```
