# PostgreSQL OTP Functions

This repository contains a set of PostgreSQL functions designed to generate and verify one-time passwords (OTPs) using TOTP (Time-Based One-Time Password) and HOTP (HMAC-Based One-Time Password) algorithms, along with utilities for Base32 encoding, URL encoding, and OTP URI generation.

## Overview

The provided SQL functions enable secure OTP generation and verification directly within a PostgreSQL database. These functions are useful for implementing two-factor authentication (2FA) or other secure token-based systems. The functions are written in SQL and PL/pgSQL, optimized for immutability and strict input validation, and include comprehensive documentation using Markdown-formatted `COMMENT ON` statements.

## Key Functions

### Core OTP Functions

- **`random_base32(_length integer)`**: Generates a random Base32-encoded string of specified length.
- **`url_encode(text)`**: Encodes a string for safe use in URLs by converting special characters to percent-encoded format.
- **`get_otp_setting_uri(_account_name text, _secret text, _issuer text, ...)`**: Creates an OTP authentication URI for TOTP or HOTP, suitable for QR code generation in 2FA apps.
- **`base32_bin(_base32 text)`**: Converts a Base32 string to its binary representation.
- **`bin_hex(_bin varbit)`**: Converts a binary string to hexadecimal format.
- **`get_otp(_secret text, ...)`**: Generates a TOTP or HOTP based on a Base32-encoded secret and other parameters.
- **`check_otp(_otp text, _secret text, ...)`**: Verifies an OTP against a secret key, supporting both TOTP and HOTP with a one-step-back tolerance.

### Secrets Table (Server-Side Verification)

A single `secrets` table stores both TOTP and HOTP secrets for server-side verification:

- **`register_secret(_id, _secret, _type, ...)`**: Registers a new TOTP or HOTP secret.
- **`verify_hotp(_id, _otp, _window)`**: HOTP verification with atomic counter update and look-ahead window.
- **`verify_totp(_id, _otp, _drift)`**: TOTP verification with configurable drift tolerance.
- **`get_secret(_id)`**: Returns stored parameters and seconds remaining (TOTP only).
- **`unregister_secret(_id)`**: Removes a secret by id.
- **`setup_secret(_id, _issuer, _type, ...)`**: Generates secret, registers it, and returns otpauth URI.

### PgArachne API Functions

Designed for [PgArachne](https://www.pgarachne.com) — a Go web server that maps PostgreSQL functions to JSON-RPC 2.0 endpoints.
All API functions accept `_params jsonb` and return `json`. PgArachne wraps them automatically.

| Function | SECURITY | Method | Payload |
|---|---|---|---|
| `enroll(jsonb)` | INVOKER | `otp.enroll` | `{"issuer": "...", "type": "totp", ...}` |
| `status(jsonb)` | INVOKER | `otp.status` | `{}` |
| `disable(jsonb)` | INVOKER | `otp.disable` | `{"otp": "123456"}` |
| `verify_login(jsonb)` | DEFINER | `otp.verify_login` | `{"user_id": "...", "otp": "..."}` |
- **Row-Level Security**: Enabled on `secrets` table. Policy: `id = current_user`.

The `secrets` table is created automatically in the `otp` schema:

| Column | Type | Description |
|---|---|---|
| `id` | `text` | Unique identifier (PK) |
| `secret` | `text` | Base32-encoded secret key |
| `type` | `text` | `'totp'` or `'hotp'` |
| `counter` | `integer` | Current counter (HOTP only, NULL for TOTP) |
| `period` | `integer` | Time period in seconds (default: 30) |
| `length` | `integer` | OTP length (default: 6) |
| `algorithm` | `text` | Hash algorithm (default: 'sha1') |
| `created_at` | `timestamptz` | Registration timestamp |
| `updated_at` | `timestamptz` | Last verification timestamp |

`verify_hotp` uses `SELECT ... FOR UPDATE` to atomically increment the counter on success. `verify_totp` checks the current time period ± `_drift` periods.

## Features

- **Persistent HOTP counters**: Server-side counter stored in a dedicated table with atomic updates.
- **Look-ahead window**: `verify_hotp()` accepts a configurable look-ahead window to handle out-of-order OTP generation.
- **TOTP drift tolerance**: `verify_totp()` accepts configurable ± periods for clock skew tolerance.
- **Comprehensive Validation**: Input validation ensures Base32 compliance and correct padding.
- **Flexible Parameters**: Supports customizable OTP length, period, algorithm, and counter for both TOTP and HOTP.
- **Markdown Documentation**: Each function includes detailed `COMMENT ON` documentation with parameter details, return types, and usage examples.

## Usage

To use these functions, execute the SQL script in your PostgreSQL database to create the functions and their comments. All functions are created in the `otp` schema. Set the search path or schema-qualify function names:

```sql
-- Option A: Set search path
SET search_path = otp, public;

-- Generate a random Base32 secret
SELECT random_base32(16); -- e.g., '4k7m2n3p5q6r8t9u'

-- Generate an OTP URI for a TOTP
SELECT get_otp_setting_uri('user@example.com', 'GEZDGNBV', 'MyApp');
-- Returns: 'otpauth://totp/user%40example.com?secret=GEZDGNBV&issuer=MyApp'

-- Generate a TOTP
SELECT get_otp('GEZDGNBV'); -- e.g., '123456'

-- Verify an OTP
SELECT check_otp('123456', 'GEZDGNBV'); -- Returns: true if valid
```

Or use schema-qualified names (no search path needed):

```sql
SELECT otp.random_base32(16);
SELECT otp.get_otp('GEZDGNBV');
SELECT otp.check_otp('123456', 'GEZDGNBV');
```

### Secrets Table Example (Server-Side Verification)

```sql
-- Register a HOTP secret for a user
SELECT register_secret('user@example.com', 'GEZDGNBV', 'hotp', _counter := 0);

-- Verify an OTP (auto-increments counter on success)
SELECT verify_hotp('user@example.com', '123456');

-- Verify with look-ahead window (accepts next 3 counters)
SELECT verify_hotp('user@example.com', '123456', _window := 3);

-- Register a TOTP secret
SELECT register_secret('user@example.com', 'GEZDGNBV', 'totp');

-- Verify a TOTP (checks current ± 1 period by default)
SELECT verify_totp('user@example.com', '123456');

-- Verify with larger drift tolerance
SELECT verify_totp('user@example.com', '123456', _drift := 2);

-- Get stored info (includes seconds_remaining for TOTP, counter for HOTP)
SELECT * FROM get_secret('user@example.com');

-- Remove secret when no longer needed
SELECT unregister_secret('user@example.com');
```

### One-Step Setup

```sql
-- Generate secret, register, and get URI for TOTP
SELECT setup_secret('user@example.com', 'MyApp', 'totp');
-- Returns: 'otpauth://totp/user%40example.com?secret=...&issuer=MyApp&period=30'

-- Generate secret, register, and get URI for HOTP
SELECT setup_secret('user@example.com', 'MyApp', 'hotp', _counter := 0);
-- Returns: 'otpauth://hotp/user%40example.com?secret=...&issuer=MyApp&counter=0'
```

## Usage Guide — Typical 2FA Workflow

### Enrollment (registering a new user for OTP)

```sql
-- 1. Generate secret, store in DB, and get URI for QR code
--    (returns e.g. 'otpauth://totp/alice@example.com?secret=...&issuer=MyApp')
SELECT setup_secret('alice@example.com', 'MyApp', 'totp');

-- 2. Show the URI as a QR code to the user (encode in QR image server-side
--    or pass to frontend). User scans it with Google Authenticator / Authy / etc.
```

For a manual setup (no `setup_secret` convenience):

```sql
-- 1. Generate a random Base32 secret
SELECT random_base32(16);

-- 2. Store it
SELECT register_secret('alice@example.com', 'GEZDGNBV', 'totp');

-- 3. Generate URI for QR code
SELECT get_otp_setting_uri('alice@example.com', 'GEZDGNBV', 'MyApp');
```

### Verification (user logging in)

```sql
-- User submits an OTP from their authenticator app.
-- Verify it against the stored secret:

-- For TOTP (time-based, most common):
SELECT verify_totp('alice@example.com', '123456');
-- Returns true/false

-- For HOTP (counter-based):
SELECT verify_hotp('alice@example.com', '123456');
-- Returns true/false; counter auto-increments on success
```

### Recovery (removing or resetting)

```sql
-- Remove OTP secret (e.g., user lost device, admin reset)
SELECT unregister_secret('alice@example.com');

-- Generate a new one
SELECT setup_secret('alice@example.com', 'MyApp', 'totp');
```

### Recommendations

| Decision | Recommendation | Reason |
|---|---|---|
| **TOTP vs HOTP** | Prefer **TOTP** | TOTP is the industry standard. Users scan a QR code, codes refresh every 30s. No counter sync issues. |
| **Hash algorithm** | `'sha1'` (default) | RFC 4226/6238 use SHA-1; all authenticator apps support it. SHA-256/512 add no practical benefit. |
| **OTP length** | `6` digits | Widest support. 8 digits work with most apps but less user-friendly. |
| **Secret length** | 16 chars (80 bits) | Sufficient entropy. Longer secrets don't improve security for TOTP/HOTP. |
| **When NOT to use** | Do NOT use `check_otp()` in production | `check_otp` is a helper for ad-hoc checks. For production, use `verify_totp`/`verify_hotp` with the `secrets` table — they handle counter sync, row locking, and drift properly. |

## PgArachne Integration

[PgArachne](https://www.pgarachne.com) is a Go web server that maps PostgreSQL functions to JSON-RPC 2.0 endpoints.
Functions with `payload jsonb` param and `json` return are exposed as API methods automatically.

### Setup

```sql
-- 1. Add the 'otp' schema to PgArachne's allowed schemas in config:
--    ALLOWED_SCHEMAS=otp

-- 2. Grant execute to authenticated roles:
GRANT USAGE ON SCHEMA otp TO app_user;
GRANT EXECUTE ON FUNCTION otp.enroll(jsonb) TO app_user;
GRANT EXECUTE ON FUNCTION otp.status(jsonb) TO app_user;
GRANT EXECUTE ON FUNCTION otp.disable(jsonb) TO app_user;

-- 3. For unauthenticated login endpoint:
GRANT EXECUTE ON FUNCTION otp.verify_login(jsonb) TO pgarachne_anonymous;
```

Row-Level Security is enabled automatically on the `otp.secrets` table. The policy restricts access so users can only see their own secret (`id = current_user`).

### API Endpoints

| Method | Role | SECURITY | Description |
|---|---|---|---|
| `otp.enroll` | authenticated | INVOKER | Generate OTP secret, return URI for QR |
| `otp.status` | authenticated | INVOKER | Check if current user has OTP |
| `otp.disable` | authenticated | INVOKER | Remove OTP after re-verification |
| `otp.verify_login` | anonymous | DEFINER | Verify OTP during login (before auth) |

### Enrollment Flow (authenticated user)

```sql
-- In PgArachne, the currently authenticated user calls:
SELECT otp.enroll('{"issuer": "MyApp"}');
-- Returns: {"enrolled": true, "type": "totp", "uri": "otpauth://totp/..."}

-- Check enrollment status:
SELECT otp.status('{}');
-- Returns: {"enabled": true}

-- Disable OTP (requires re-verification):
SELECT otp.disable('{"otp": "123456"}');
-- Returns: {"disabled": true}
```

### Login Flow (unauthenticated user)

```sql
-- During login, PgArachne runs this as the anonymous role:
SELECT otp.verify_login('{"user_id": "alice@example.com", "otp": "123456"}');
-- Returns: {"valid": true} or {"valid": false}
```

`verify_login` uses `SECURITY DEFINER` to read the secret for any user, but never exposes the secret value — only returns a boolean.

## Requirements

## Installation

1. Clone this repository or download the `otp.sql` file.
2. Run the SQL script in your PostgreSQL database:
   ```bash
   psql -U your_user -d your_database -f otp.sql
   ```
3. Ensure the `pgcrypto` extension is enabled as noted above.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.