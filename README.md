# PostgreSQL OTP Functions

This repository contains a set of PostgreSQL functions designed to generate and verify one-time passwords (OTPs) using TOTP (Time-Based One-Time Password) and HOTP (HMAC-Based One-Time Password) algorithms, along with utilities for Base32 encoding, URL encoding, and OTP URI generation.

## Overview

The provided SQL functions enable secure OTP generation and verification directly within a PostgreSQL database. These functions are useful for implementing two-factor authentication (2FA) or other secure token-based systems. The functions are written in SQL and PL/pgSQL, optimized for immutability and strict input validation, and include comprehensive documentation using Markdown-formatted `COMMENT ON` statements.

## Key Functions

- **`random_base32(_length integer)`**: Generates a random Base32-encoded string of specified length.
- **`url_encode(text)`**: Encodes a string for safe use in URLs by converting special characters to percent-encoded format.
- **`get_otp_setting_uri(_account_name text, _secret text, _issuer text, ...)`**: Creates an OTP authentication URI for TOTP or HOTP, suitable for QR code generation in 2FA apps.
- **`base32_bin(_base32 text)`**: Converts a Base32 string to its binary representation.
- **`bin_hex(_bin bit)`**: Converts a binary string to hexadecimal format.
- **`get_otp(_secret text, ...)`**: Generates a TOTP or HOTP based on a Base32-encoded secret and other parameters.
- **`check_otp(_otp text, _secret text, ...)`**: Verifies an OTP against a secret key, supporting both TOTP and HOTP with a one-step-back tolerance.

## Features

- **Immutable and Strict**: All functions are marked `IMMUTABLE` and `STRICT` for performance and reliability.
- **Comprehensive Validation**: Input validation ensures Base32 compliance and correct padding.
- **Flexible Parameters**: Supports customizable OTP length, period, algorithm, and counter for both TOTP and HOTP.
- **Markdown Documentation**: Each function includes detailed `COMMENT ON` documentation with parameter details, return types, and usage examples.

## Usage

To use these functions, execute the SQL script in your PostgreSQL database to create the functions and their comments. Example usage:

```sql
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

## Requirements

- PostgreSQL 9.6 or later (due to use of `encode`, `decode`, and `hmac` functions).
- The `pgcrypto` extension must be enabled for HMAC functionality:
  ```sql
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
  ```

## Installation

1. Clone this repository or download the `otp_functions.sql` file.
2. Run the SQL script in your PostgreSQL database:
   ```bash
   psql -U your_user -d your_database -f otp_functions.sql
   ```
3. Ensure the `pgcrypto` extension is enabled as noted above.

## License

This project is licensed under the BSD 3-Clause License. See the [LICENSE](LICENSE) file for details.