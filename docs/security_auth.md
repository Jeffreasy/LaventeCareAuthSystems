# Authentication & Cryptography

## 🔐 The Core Mechanics
This system implements a comprehensive Headless Auth Provider. Security is paramount.

### Password Storage
- **Algorithm**: Bcrypt (`golang.org/x/crypto/bcrypt`)
- **Cost**: **12** (Hardened for 2026 standards).
- **Policy**:
    - Min Length: 12 characters.
    - Max Length: 72 bytes.

### Token Strategy
We use **JWT (HS256)** with a **Dual-Token System** (Access + Refresh) to balance security and UX.

#### 1. Access Token (JWT)
- **Format**: JSON Web Token (Signed).
- **Algorithm**: `HS256` (HMAC-SHA256).
- **Lifespan**: Short (e.g., 15 minutes).
- **Storage**: Client-side memory or HttpOnly Cookie.
- **Claims**:
    - `sub`: User UUID.
    - `tid`: Tenant UUID (Context).
    - `role`: User Role (admin/editor/viewer).
    - `exp`: Unix Timestamp Expiry.
    - `iss`: "laventecare-auth".

#### 2. Refresh Token (Opaque)
- **Lifespan**: Long (e.g., 7-30 days).
- **Storage**: `refresh_tokens` table (Hashed).
- **Rotation**: Refresh tokens are rotated on use. Old tokens are invalidated to prevent replay attacks (Reuse Detection).

---

## ⚠️ Active Defense & Anti-Gravity Measures

### Active Defense Layers
- **Rate Limiting**: IP-based Token Bucket (5 req/s) prevents brute-force.
- **Tenant Context**: `X-Tenant-ID` header is cryptographically validated middleware-side layer before hitting business logic.
- **Strict Headers**: `Content-Type: application/json` is mandatory.

### "Input is Toxic"
- **Registration**: Emails are validated via `net/mail`.
- **Login**: Unknown JSON fields cause immediate rejection.

### "Silence is Golden"
- **Login Errors**: Generic "Invalid credentials" messages.
- **Timing Attacks**: `subtle.ConstantTimeCompare` for all crypto checks.
- **User Enumeration Prevention**: Password Reset flows return "Success" even if the email does not exist.

---

## 📋 Resilience Flows

### Password Reset
1.  **Request**: User submits email.
2.  **Gen**: Server generates highly random 32-byte token.
3.  **Hash**: SHA256 hash stored in `verification_tokens` (15m expiry).
4.  **Send**: Raw token sent via Email (simulated).
5.  **Use**: User submits Raw Token + New Password.
6.  **Verify**: Server hashes input -> Looks up DB -> Checks Expiry -> Resets Password -> **Deletes Token**.

### Email Verification
 Similar to Password Reset, but validates ownership of the email address. Uses `verification_tokens` with 24h expiry.

### Secure Logout
1.  User requests Logout with Refresh Token.
2.  Server identifies the **Token Family**.
3.  Server **Revokes** the entire family in DB.
4.  Effect: All sessions on that device (and cloned tokens) are killed immediately.

---

## 📋 Flows

### Registration
1.  Parse & Validate JSON.
2.  Check if Email exists (if yes, return generic 200 OK or error stealthily).
3.  Hash Password.
4.  Create `User` record.
5.  Create Default `Tenant` (if applicable).
6.  Create `Membership`.

### Login Flow (with MFA)
1.  **Request**: `POST /auth/login` with Email/Password.
2.  **MFA Check**:
    - If user has `mfa_enabled = true`:
        - Return `200 OK` with `{ "mfa_required": true, "user": ... }`.
        - **No Tokens Issued yet.**
    - If `mfa_enabled = false`:
        - Issue Access/Refresh tokens immediately.
3.  **MFA Verify**:
    - **Request**: `POST /auth/mfa/verify` (TOTP) or `POST /auth/mfa/backup` (Recovery Code).
    - **Input**: UserID + Code.
    - **Result**: Issue Access/Refresh tokens.

### Backup Codes (Phase 14)
- **Generation**: Created during MFA setup. 10 codes (Current implementation uses `crypto/rand` for secure generation).
- **Storage**: SHA256 hashed in `mfa_backup_codes`.
- **Usage**: One-time use. Deleted/Marked used upon validation.

---

## 🍪 Cookie Security (CSRF)
We use the **Double-Submit Cookie Pattern** to secure state-changing requests.
1.  **Cookie**: `csrf_token` (Not HttpOnly, readable by JS).
2.  **Header**: Client must read cookie and send value in `X-CSRF-Token` header.
3.  **Middleware**: Validates equality for `POST`, `PUT`, `DELETE`.

---

## 🛡️ Access Control (RBAC) & Invitations
We enforce roles via `memberships` table linking Users to Tenants.

### Roles
- **Admin**: Full access to tenant resources.
- **Editor**: Can modify data, cannot delete tenant or manage billing.
- **Viewer**: Read-only access.

### Enforcement
- **Middleware**: `RBACMiddleware(requiredRole)`.
- **Logic**:
    1. Extract `userID` and `role` from context (Injected from Token).
    2. Zero-Latency Check (No Database Query).
    3. Verify role hierarchy (`admin` > `editor` > `viewer`).
- **Failure**: Returns `403 Forbidden` if role is insufficient.
