# Secure POS — Developer Manual

**Course:** SOFE4840U — Software Quality Assurance
**Group:** 5
**System:** Secure Purchase Order System

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [File Structure](#2-file-structure)
3. [Setup and Running](#3-setup-and-running)
4. [Configuration — config.py](#4-configuration--configpy)
5. [Application Entry Point — app.py](#5-application-entry-point--apppy)
6. [Authentication and RBAC — auth.py](#6-authentication-and-rbac--authpy)
7. [Order Workflow — orders.py](#7-order-workflow--orderspy)
8. [Database Layer — database.py](#8-database-layer--databasepy)
9. [Cryptography Module — crypto.py](#9-cryptography-module--cryptopy)
10. [Database Schema](#10-database-schema)
11. [Templates](#11-templates)
12. [Security Properties](#12-security-properties)
13. [Order Lifecycle](#13-order-lifecycle)

---

## 1. Project Overview

Secure POS is a three-role purchase order system where every order is:

- **Encrypted** with the recipient's RSA public key so only the intended party can read it
- **Hashed** with SHA-256 over the order content and a timestamp
- **Signed** by the purchaser at submission and co-signed by the supervisor at approval
- **Re-encrypted** at each handoff so only the current role's holder can decrypt it

The cryptographic chain creates a tamper-evident audit trail. The orders department cannot process an order unless both signatures verify against the original content.

**Roles and their permissions:**

| Role | What they can do |
|------|-----------------|
| `purchaser` | Submit orders, view their own order history |
| `supervisor` | View pending orders assigned to them, approve or reject |
| `orders_dept` | View approved orders, verify both signatures, mark as processed |

---

## 2. File Structure

```
secure_pos/
├── app.py                  # Flask app factory, extensions, error handlers
├── auth.py                 # Registration, login, logout, RBAC decorator
├── orders.py               # All order routes (create, approve, reject, process, dashboards)
├── database.py             # All SQLite operations
├── crypto.py               # All cryptographic operations (do not modify)
├── config.py               # Configuration constants loaded at startup
├── requirements.txt        # Python dependencies
├── .gitignore
├── .secret_key             # Auto-generated persistent secret key (not committed)
├── pos.db                  # SQLite database (not committed)
├── .flask_sessions/        # Server-side session files (not committed)
└── templates/
    ├── base.html
    ├── login.html
    ├── register.html
    ├── purchaser_dashboard.html
    ├── supervisor_dashboard.html
    ├── orders_dashboard.html
    └── error.html
```

---

## 3. Setup and Running

```bash
pip install -r requirements.txt
python app.py
```

The app runs on http://localhost:5000 with `debug=False`.

On first run, `app.py` calls `db.init_db()` which creates `pos.db` and all tables if they do not exist. It also creates `.flask_sessions/` for server-side session storage and generates `.secret_key` if it does not exist.

**To reset everything** (wipe all users and orders):
```bash
rm -f pos.db .secret_key
python app.py
```

**Environment variables:**

| Variable | Default | Effect |
|----------|---------|--------|
| `SECRET_KEY` | _(reads `.secret_key` file)_ | Overrides the file-based key |
| `PRODUCTION` | `false` | Set to `true` to enable `SESSION_COOKIE_SECURE` (HTTPS only) |

---

## 4. Configuration — config.py

All values are module-level constants imported by other modules.

| Name | Type | Value / Source | Purpose |
|------|------|----------------|---------|
| `SECRET_KEY` | `str` | Read from `.secret_key` file; generated once if absent | Flask session signing key |
| `DATABASE` | `str` | `"pos.db"` | SQLite file path |
| `PERMANENT_SESSION_LIFETIME` | `int` | `1800` | Session timeout in seconds (30 min) |
| `SESSION_FILE_DIR` | `str` | `".flask_sessions"` | Directory for server-side session files |
| `SESSION_TYPE` | `str` | `"filesystem"` | Flask-Session backend type |
| `WTF_CSRF_ENABLED` | `bool` | `True` | Enables CSRF protection globally |
| `WTF_CSRF_TIME_LIMIT` | `int` | `3600` | CSRF token lifetime in seconds |
| `SESSION_COOKIE_SECURE` | `bool` | `False` unless `PRODUCTION=true` env var | Restricts session cookie to HTTPS |

The `.secret_key` file mechanism: on first startup the file is created with `os.urandom(32).hex()`. On subsequent startups the same key is reused, so sessions survive server restarts without hardcoding anything or requiring an environment variable.

---

## 5. Application Entry Point — app.py

Initialises Flask and all extensions, registers blueprints, and defines error handlers.

### Extensions configured

**Flask-Session** — server-side filesystem sessions. The browser cookie contains only a signed session ID. The actual session data (including the decrypted private key) lives in `.flask_sessions/` on the server.

Session cookie flags set:
- `SESSION_USE_SIGNER = True` — session ID is HMAC-signed
- `SESSION_COOKIE_HTTPONLY = True` — cookie not accessible from JavaScript
- `SESSION_COOKIE_SAMESITE = "Lax"` — CSRF mitigation
- `SESSION_COOKIE_SECURE` — controlled by `config.SESSION_COOKIE_SECURE`

**Flask-WTF CSRFProtect** — enforces a CSRF token on every state-changing form POST. All templates include `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>`.

**Flask-Limiter** — rate limiting keyed by remote IP address.
- `POST /login` — 10 requests per minute
- `POST /register` — 5 requests per minute

### Error handlers

| Code | Message shown to user | Server behaviour |
|------|-----------------------|-----------------|
| 403 | "You do not have permission to access this page." | Renders `error.html` |
| 404 | "Page not found." | Renders `error.html` |
| 500 | "An internal error occurred." | Logs full exception via `app.logger.exception`, renders `error.html` |

Stack traces are never exposed to the browser.

### Startup sequence

```
config.py loaded
  -> .secret_key read or created
  -> Session extension initialised
  -> CSRFProtect initialised
  -> Rate limiter initialised
  -> Blueprints registered (auth_bp, orders_bp)
  -> Rate limits attached to login/register view functions
  -> db.init_db() called inside app context
```

---

## 6. Authentication and RBAC — auth.py

**Blueprint:** `auth_bp` (no URL prefix)

### `require_role(*roles)` — decorator

```python
@require_role("purchaser")
def some_route(): ...
```

Wraps a route function. Checks `session["user_id"]` exists (redirects to `/login` if not) and that `session["role"]` is one of the allowed roles (aborts 403 if not). Accepts multiple roles: `@require_role("supervisor", "orders_dept")`.

### Routes

#### `GET /` — `index()`
Redirects to `/dashboard` if logged in, otherwise to `/login`.

#### `GET /register` — `register()`
Renders `register.html`.

#### `POST /register` — `register()`
Rate limited to 5/minute per IP.

**Validation (in order):**
1. Username: matches `^[\w]{3,30}$` (letters, digits, underscores, 3–30 chars)
2. Password: length >= 8, contains at least one letter and one digit
3. All fields present (username, password, role)
4. Passwords match
5. Role is one of `purchaser`, `supervisor`, `orders_dept`
6. Username not already taken

**On success:**
1. Hashes password with bcrypt (random salt, default cost factor)
2. Generates RSA-2048 key pair
3. Derives 256-bit AES key from password using PBKDF2-HMAC-SHA256 (100,000 iterations, 16-byte random salt)
4. Encrypts private key PEM with AES-256-GCM; stores as `base64(salt[16] || nonce[16] || tag[16] || ciphertext)`
5. Calls `db.insert_user()` inside a try/except — database errors flash a message instead of raising a 500
6. Redirects to `/login`

#### `GET /login` — `login()`
Renders `login.html`.

#### `POST /login` — `login()`
Rate limited to 10/minute per IP.

1. Looks up user by username
2. Verifies bcrypt password hash — same code path for "user not found" and "wrong password" (no username enumeration)
3. Calls `crypto.decrypt_private_key()` to recover the private key PEM using the submitted password
4. Stores in server-side session: `user_id`, `username`, `role`, `decrypted_private_key`
5. Writes `login` audit log entry
6. Redirects to `/dashboard`

#### `GET /logout` — `logout()`
Writes `logout` audit log entry, clears session, redirects to `/login`.

#### `GET /dashboard` — `dashboard()`
Reads `session["role"]` and redirects:
- `purchaser` → `/dashboard/purchaser`
- `supervisor` → `/dashboard/supervisor`
- `orders_dept` → `/dashboard/orders`
- anything else → `/login`

---

## 7. Order Workflow — orders.py

**Blueprint:** `orders_bp` (no URL prefix)

### Purchaser routes

#### `POST /order/create` — `create_order()`
Requires role: `purchaser`

**Input validation:**

| Field | Form name | Rules |
|-------|-----------|-------|
| Item description | `items` | 1–200 chars, regex `^[\w\s\-\.,/()]+$` |
| Quantity | `quantity` | Integer 1–10,000 |
| Unit price | `unit_price` | Float > 0, <= 1,000,000 |
| Vendor | `vendor` | 1–100 chars, regex `^[\w\s\-\.,/()&]+$` |
| Justification | `justification` | 10–1,000 chars |

All validation errors are collected and flashed before redirecting — the user sees all problems at once.

**On valid input:**
1. Builds `order_data` dict with a new UUID, validated fields (quantity as string, unit_price formatted to 2 decimal places)
2. Takes a UTC timestamp
3. Calls `crypto.hash_order(order_data, timestamp)` → SHA-256 hex digest
4. Calls `crypto.sign_data(session["decrypted_private_key"], order_hash, timestamp)` → base64 RSA-PSS signature
5. Calls `crypto.encrypt_for_recipient(supervisor["public_key"], json.dumps(order_data))` → hybrid-encrypted bundle
6. Calls `db.insert_order()` with all fields plus `order_meta=json.dumps(order_data)` (plaintext copy for purchaser history)
7. Writes `order_created` audit log entry

**Why `order_meta`?** Once the supervisor approves, the payload is re-encrypted for the orders department and the purchaser can no longer decrypt it. `order_meta` stores the plaintext so the purchaser's dashboard always shows real order details.

#### `GET /dashboard/purchaser` — `purchaser_dashboard()`
Requires role: `purchaser`

Fetches all orders for the logged-in purchaser. For each order, reads display fields from `order_meta` (the stored plaintext JSON). Falls back to `"(encrypted)"` / `"-"` for orders created before `order_meta` was added. Renders `purchaser_dashboard.html`.

### Supervisor routes

#### `POST /order/<int:order_id>/approve` — `approve_order(order_id)`
Requires role: `supervisor`

Guards:
- Order must exist (404 if not)
- Order status must be `pending` (flashes warning if not)
- `order["supervisor_id"]` must match `session["user_id"]` (403 if not — supervisors cannot approve orders assigned to other supervisors)

**Approval steps:**
1. Decrypts `encrypted_payload` using supervisor's private key from session
2. Verifies purchaser's RSA-PSS signature against the order hash + purchaser timestamp — aborts with danger flash if invalid, writes `signature_verification_failed` audit entry
3. Co-signs: takes a new timestamp, calls `crypto.sign_data()` with the supervisor's private key over the same `order_hash` + new timestamp
4. Looks up the orders department user — aborts if none registered
5. Re-encrypts the order plaintext for the orders department user's public key
6. Updates order: `status="approved"`, `encrypted_payload=re_encrypted`, `supervisor_signature`, `supervisor_timestamp`
7. Writes `order_approved` audit entry

#### `POST /order/<int:order_id>/reject` — `reject_order(order_id)`
Requires role: `supervisor`

Same guards as approve (existence, status, ownership). Updates `status="rejected"`. Writes `order_rejected` audit entry.

#### `GET /dashboard/supervisor` — `supervisor_dashboard()`
Requires role: `supervisor`

Fetches all `pending` orders where `supervisor_id` matches the logged-in user. For each order, decrypts the payload and looks up the purchaser's username. Decryption failures are caught silently (order still shown, `purchaser_name` set to `"Unknown"`). Renders `supervisor_dashboard.html`.

### Orders department routes

#### `POST /order/<int:order_id>/process` — `process_order(order_id)`
Requires role: `orders_dept`

Guards:
- Order must exist (404 if not)
- Order status must be `approved`

**Processing steps:**
1. Decrypts `encrypted_payload` with the orders dept user's private key
2. Looks up purchaser by `purchaser_id` — flashes error and redirects if account no longer exists
3. Verifies purchaser RSA-PSS signature
4. Looks up supervisor by `supervisor_id` — flashes error and redirects if account no longer exists
5. Verifies supervisor RSA-PSS signature
6. If either signature fails: flashes danger message, writes `signature_verification_failed` audit entry, redirects
7. If both valid: updates `status="processed"`, writes `order_processed` audit entry

#### `GET /dashboard/orders` — `orders_dashboard()`
Requires role: `orders_dept`

Fetches all `approved` orders (ordered by `updated_at DESC`). For each order:
1. Decrypts payload
2. Looks up purchaser and supervisor — if either account is deleted, sets that signature valid flag to `False` without crashing
3. Verifies both signatures, stores `purchaser_sig_valid` and `supervisor_sig_valid` as booleans
4. Any decryption exception sets both flags to `False`

Renders `orders_dashboard.html`.

---

## 8. Database Layer — database.py

All functions open a new SQLite connection, perform one operation, commit, and close. `conn.row_factory = sqlite3.Row` is set on every connection so rows can be accessed by column name.

### Functions

#### `get_db() -> sqlite3.Connection`
Opens and returns a connection to `config.DATABASE`. Sets `row_factory = sqlite3.Row`.

#### `init_db()`
Runs `CREATE TABLE IF NOT EXISTS` for all three tables. Called once inside the Flask app context at startup.

#### `get_user_by_username(username) -> Row | None`
`SELECT * FROM users WHERE username = ?`. Returns a Row or None.

#### `get_user_by_id(user_id) -> Row | None`
`SELECT * FROM users WHERE id = ?`. Returns a Row or None. Callers must check for None before accessing fields.

#### `insert_user(username, password_hash, role, public_key, encrypted_private_key)`
Inserts a new user. Raises `sqlite3.IntegrityError` on duplicate username (the `UNIQUE NOT NULL` constraint). The register route wraps this in try/except.

#### `get_first_user_by_role(role) -> Row | None`
`SELECT * FROM users WHERE role = ? LIMIT 1`. Returns the first user with that role or None.

#### `get_supervisor() -> Row | None`
Calls `get_first_user_by_role("supervisor")`. The system uses only the first registered supervisor.

#### `get_orders_dept_user() -> Row | None`
Calls `get_first_user_by_role("orders_dept")`. The system uses only the first registered orders dept user.

#### `insert_order(order_uid, purchaser_id, supervisor_id, encrypted_payload, purchaser_signature, purchaser_timestamp, status, created_at, order_meta=None)`
Inserts a new order row. `order_meta` is optional (defaults to None) for backwards compatibility. `updated_at` is set to the same value as `created_at` on insert.

#### `get_order(order_id) -> Row | None`
`SELECT * FROM orders WHERE id = ?`.

#### `get_orders_by_purchaser(purchaser_id) -> list[Row]`
`SELECT * FROM orders WHERE purchaser_id = ? ORDER BY created_at DESC`.

#### `get_orders_by_supervisor(supervisor_id) -> list[Row]`
`SELECT * FROM orders WHERE supervisor_id = ? AND status = 'pending' ORDER BY created_at DESC`. Only returns pending orders.

#### `get_approved_orders() -> list[Row]`
`SELECT * FROM orders WHERE status = 'approved' ORDER BY updated_at DESC`.

#### `update_order(order_id, **fields)`
Updates an order by ID. Field names are validated against a whitelist before being interpolated into the SQL `SET` clause. `updated_at` is always set to the current UTC time.

**Allowed fields:**
- `status`
- `encrypted_payload`
- `supervisor_signature`
- `supervisor_timestamp`

Passing any other field name raises `ValueError` immediately.

#### `write_audit_log(user_id, action, order_id=None)`
Inserts a row into `audit_log` with the current UTC timestamp.

**Known action strings used in the codebase:**

| Action | Written by |
|--------|-----------|
| `login` | `auth.login` |
| `logout` | `auth.logout` |
| `order_created` | `orders.create_order` |
| `order_approved` | `orders.approve_order` |
| `order_rejected` | `orders.reject_order` |
| `order_processed` | `orders.process_order` |
| `signature_verification_failed` | `orders.approve_order`, `orders.process_order` |

---

## 9. Cryptography Module — crypto.py

**Do not modify this file.** All functions are stateless — they take arguments and return results without touching the database or Flask session.

### `hash_order(order_data: dict, timestamp: str) -> str`
Serialises `order_data` to JSON with sorted keys (deterministic), appends `timestamp`, and returns a SHA-256 hex digest. The timestamp is included in the hash so the hash commits to when the order was created.

### `sign_data(private_key_pem: str, order_hash: str, timestamp: str) -> str`
Signs `(order_hash + timestamp)` with RSA-PSS-SHA256 using the given private key PEM. Returns a base64-encoded signature string safe to store as TEXT in SQLite. The timestamp in the signature input is the signer's own timestamp (different from the purchaser's timestamp for supervisor co-signatures).

### `verify_signature(public_key_pem: str, signature_b64: str, order_hash: str, timestamp: str) -> bool`
Verifies a signature produced by `sign_data`. Returns `True` if valid, `False` for any failure (wrong key, tampered data, corrupt signature). Never raises an exception to callers.

### `encrypt_for_recipient(public_key_pem: str, plaintext: str) -> str`
Hybrid encryption:
1. Generates a random 256-bit AES session key
2. Encrypts `plaintext` with AES-256-GCM (produces ciphertext + authentication tag)
3. Encrypts the AES key with the recipient's RSA-2048 public key using OAEP-SHA256
4. Bundles `{enc_key, nonce, tag, ct}` as JSON, base64-encodes the whole bundle

Returns a base64 string safe to store as TEXT in SQLite. Only the holder of the corresponding private key can decrypt.

### `decrypt_payload(private_key_pem: str, encrypted_bundle: str) -> str`
Reverses `encrypt_for_recipient`. Raises `ValueError` if the AES-GCM authentication tag does not match (tampered ciphertext). Raises on RSA decryption failure (wrong private key). Callers wrap this in try/except.

### `decrypt_private_key(encrypted_priv_b64: str, password: str) -> str`
Recovers a user's RSA private key PEM from its encrypted storage format. The storage format produced by the register route is `base64(salt[16] || nonce[16] || tag[16] || ciphertext)`. This function re-derives the AES key using PBKDF2-HMAC-SHA256 with 100,000 iterations and decrypts with AES-256-GCM. Raises `ValueError` on wrong password or corrupted data.

---

## 10. Database Schema

### `users`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Internal user ID |
| `username` | TEXT | UNIQUE NOT NULL | Login name |
| `password_hash` | TEXT | NOT NULL | bcrypt hash (includes salt) |
| `role` | TEXT | NOT NULL | One of: `purchaser`, `supervisor`, `orders_dept` |
| `public_key` | TEXT | NOT NULL | RSA-2048 public key in PEM format |
| `encrypted_private_key` | TEXT | NOT NULL | `base64(salt[16] \|\| nonce[16] \|\| tag[16] \|\| ciphertext)` |

### `orders`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Internal order ID (used in URLs) |
| `order_uid` | TEXT | UNIQUE NOT NULL | UUID generated at order creation |
| `purchaser_id` | INTEGER | NOT NULL | FK → `users.id` |
| `supervisor_id` | INTEGER | | FK → `users.id` (first registered supervisor at time of submission) |
| `status` | TEXT | NOT NULL DEFAULT 'pending' | One of: `pending`, `approved`, `rejected`, `processed` |
| `encrypted_payload` | TEXT | NOT NULL | Hybrid-encrypted order JSON; recipient changes at each stage |
| `purchaser_signature` | TEXT | NOT NULL | Base64 RSA-PSS signature by purchaser |
| `purchaser_timestamp` | TEXT | NOT NULL | ISO-8601 UTC timestamp at submission; used as nonce in hash |
| `supervisor_signature` | TEXT | | Base64 RSA-PSS co-signature by supervisor; NULL until approved |
| `supervisor_timestamp` | TEXT | | ISO-8601 UTC timestamp at approval; NULL until approved |
| `created_at` | TEXT | NOT NULL | ISO-8601 UTC timestamp at row creation |
| `updated_at` | TEXT | NOT NULL | ISO-8601 UTC timestamp of last update |
| `order_meta` | TEXT | | JSON copy of order fields in plaintext; used by purchaser dashboard |

**Note on `encrypted_payload` recipient lifecycle:**

| Status | Encrypted for |
|--------|--------------|
| `pending` | Supervisor's public key |
| `approved` | Orders dept user's public key |
| `rejected` | Supervisor's public key (unchanged) |
| `processed` | Orders dept user's public key (unchanged) |

### `audit_log`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | |
| `user_id` | INTEGER | NOT NULL | User who performed the action |
| `action` | TEXT | NOT NULL | Action string (see table in section 8) |
| `order_id` | TEXT | | Order UID or numeric ID; NULL for login/logout events |
| `timestamp` | TEXT | NOT NULL | ISO-8601 UTC timestamp |

---

## 11. Templates

All templates extend `base.html`. All form templates include a CSRF token hidden input.

### `base.html`
Defines the page shell: Bootstrap 5.3 CSS/JS from CDN, Ontario Tech colour variables (`--ot-navy: #002654`, `--ot-orange: #E4610F`), navbar (shown only when `session.username` is set), flash message rendering with dismissible alerts, and a footer.

### `login.html`
Single form: `username`, `password`. Posts to `POST /login`.

### `register.html`
Single form: `username`, `password`, `confirm_password`, `role` (select). Posts to `POST /register`. Placeholder text shows password requirements.

### `purchaser_dashboard.html`
Two sections:
- **New Order form** — posts to `POST /order/create`. Fields: `items`, `quantity`, `unit_price`, `vendor`, `justification` with HTML `min`/`max`/`maxlength` constraints matching server-side validation.
- **My Orders table** — columns: Order ID (first 8 chars of UUID), Vendor, Items, Qty, Unit Price, Status (styled badge), Submitted. Data comes from `order_meta`.

### `supervisor_dashboard.html`
One card per pending order showing: Vendor, Items (`item_description`), Quantity, Unit Price, calculated Total, Purchaser name, Submitted timestamp, Justification. Two forms per card: Approve (`POST /order/<id>/approve`) and Reject (`POST /order/<id>/reject`), each with a confirmation dialog.

### `orders_dashboard.html`
One card per approved order showing: all order fields, calculated Total, Purchaser name, Supervisor name, Submitted timestamp, and a signature verification panel showing Verified/Invalid for both signatures. Process Order button (`POST /order/<id>/process`) is disabled when either signature is invalid.

### `error.html`
Displays `{{ code }}` in large orange text and `{{ message }}` below it with a link back to `/dashboard`.

---

## 12. Security Properties

### What the cryptographic workflow guarantees

**Confidentiality** — Order contents are always encrypted with the current recipient's public key. The purchaser cannot read the order after the supervisor approves it (re-encrypted for orders dept). The supervisor cannot read approved orders either.

**Integrity** — The SHA-256 hash covers the full order content plus the purchaser timestamp. Any modification to any field changes the hash, causing signature verification to fail.

**Non-repudiation** — The purchaser's signature commits to the order content and their submission timestamp. The supervisor's co-signature commits to the same order hash and their own approval timestamp. Neither party can later deny having performed their action without the signature becoming invalid.

**Authentication** — Private keys are encrypted with a key derived from the user's password (PBKDF2, 100,000 iterations). The plaintext private key exists only in server-side session memory during an active session. It is never written to disk in plaintext and never sent to the browser.

### Session security

- Sessions are stored server-side in `.flask_sessions/`. The browser receives only a signed session ID.
- `HttpOnly` prevents JavaScript access to the cookie.
- `SameSite=Lax` prevents cross-site request forgery for top-level navigations.
- `SESSION_COOKIE_SECURE` should be set to `true` in production (via `PRODUCTION=true` env var) to restrict the cookie to HTTPS connections.
- CSRF tokens (Flask-WTF) protect all state-changing POST forms.

### Rate limiting

- Login: 10 POST requests per minute per IP
- Register: 5 POST requests per minute per IP
- All other routes: no limit (authenticated routes require a valid session)

### Input validation

All order fields are validated server-side with whitelist regex patterns before any cryptographic or database operation is performed. The HTML form attributes (`min`, `max`, `maxlength`, `minlength`) are UI hints only — they are not relied upon for security.

---

## 13. Order Lifecycle

```
[Purchaser]
  POST /order/create
    -> validate fields
    -> hash order + timestamp
    -> sign with purchaser private key
    -> encrypt for supervisor public key
    -> INSERT order (status=pending, order_meta=plaintext)
    -> write audit: order_created

[Supervisor]
  GET /dashboard/supervisor
    -> fetch pending orders
    -> decrypt each with supervisor private key to display

  POST /order/<id>/approve
    -> decrypt payload
    -> verify purchaser signature  <-- aborts if invalid
    -> co-sign with supervisor private key + new timestamp
    -> re-encrypt for orders dept public key
    -> UPDATE order (status=approved, new encrypted_payload, supervisor sig/timestamp)
    -> write audit: order_approved

  POST /order/<id>/reject
    -> UPDATE order (status=rejected)
    -> write audit: order_rejected

[Orders Dept]
  GET /dashboard/orders
    -> fetch approved orders
    -> decrypt each with orders dept private key
    -> verify both signatures, show Verified/Invalid

  POST /order/<id>/process
    -> decrypt payload
    -> verify purchaser signature
    -> verify supervisor signature
    -> UPDATE order (status=processed)
    -> write audit: order_processed
```
