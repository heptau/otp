-- PostgreSQL OTP Functions v1.0.0
-- Generates and verifies TOTP/HOTP one-time passwords directly in PostgreSQL.
-- License: MIT

SET client_min_messages = warning;

CREATE SCHEMA IF NOT EXISTS otp;

DROP FUNCTION IF EXISTS otp.random_base32(integer) CASCADE;

CREATE FUNCTION otp.random_base32(_length integer = 16)
RETURNS text
LANGUAGE SQL
STRICT STABLE
AS $fn$
	SELECT string_agg(
		substring('234567abcdefghijklmnopqrstuvwxyz' FROM (get_byte(gen_random_bytes(1), 0) % 32 + 1) FOR 1),
		'' ORDER BY n
	)
	FROM generate_series(1, _length) AS n;
$fn$;

COMMENT ON FUNCTION otp.random_base32(integer) IS
$$
# Random Base32 Generator

Generates a random Base32 string of specified length.

### Param details
- `_length` (integer): Length of the generated Base32 string (default: 16).

### Returns
- `text`: Random Base32 string.

### Examples
```sql
SELECT random_base32(10); -- Returns a 10-character Base32 string, e.g., '2a3b4c5d6e'
```
$$;

DROP FUNCTION IF EXISTS otp.url_encode(text) CASCADE;

CREATE FUNCTION otp.url_encode(text)
RETURNS text
LANGUAGE SQL
STRICT IMMUTABLE
AS $fn$
	SELECT string_agg(
		CASE WHEN ch ~ '[0-9a-zA-Z:/@._?#-]' THEN ch
			ELSE regexp_replace(upper(encode(ch::bytea, 'hex')), '(..)', E'%\\1', 'g')
		END, '')
	FROM regexp_split_to_table($1, '') AS ch;
$fn$;

COMMENT ON FUNCTION otp.url_encode(text) IS
$$
# URL Encode Function

Encodes a string for use in URLs by converting special characters to percent-encoded format.

### Param details
- `text` (text): Input string to encode.

### Returns
- `text`: URL-encoded string.

### Examples
```sql
SELECT url_encode('user@example.com'); -- Returns 'user%40example.com'
```
$$;

DROP FUNCTION IF EXISTS otp.get_otp_setting_uri(text, text, text, integer, integer, text) CASCADE;

CREATE FUNCTION otp.get_otp_setting_uri(
	_account_name text,
	_secret text,
	_issuer text,
	_counter integer = NULL,
	_period integer = NULL,
	_algorithm text = NULL)
RETURNS text
LANGUAGE SQL
IMMUTABLE
AS $fn$
	SELECT concat(
		'otpauth://', CASE WHEN _counter IS NULL THEN 'totp' ELSE 'hotp' END,
		'/', otp.url_encode(_account_name),
		'?secret=', otp.url_encode(_secret),
		'&issuer=' || otp.url_encode(_issuer),
		CASE WHEN _counter IS NOT NULL THEN '&counter=' || _counter ELSE '' END,
		CASE WHEN _period IS NOT NULL THEN '&period=' || _period ELSE '' END,
		CASE WHEN _algorithm IS NOT NULL THEN '&algorithm=' || otp.url_encode(_algorithm) ELSE '' END
	);
$fn$;

COMMENT ON FUNCTION otp.get_otp_setting_uri(text, text, text, integer, integer, text) IS
$$
# OTP Setting URI Generator

Generates an OTP authentication URI for TOTP or HOTP.

### Param details
- `_account_name` (text): Account name to include in the URI.
- `_secret` (text): Base32-encoded secret key.
- `_issuer` (text): Issuer name for the OTP.
- `_counter` (integer, optional): Counter for HOTP (NULL for TOTP).
- `_period` (integer, optional): Time period for TOTP in seconds.
- `_algorithm` (text, optional): Hash algorithm (e.g., 'sha1').

### Returns
- `text`: OTP authentication URI.

### Examples
```sql
SELECT get_otp_setting_uri('user@example.com', 'GEZDGNBV', 'MyApp'); 
-- Returns 'otpauth://totp/user%40example.com?secret=GEZDGNBV&issuer=MyApp'
```
$$;

DROP FUNCTION IF EXISTS otp.base32_bin(text) CASCADE;

CREATE FUNCTION otp.base32_bin(_base32 text)
RETURNS bit
LANGUAGE SQL
STRICT IMMUTABLE
AS $fn$
	WITH chars2bits AS (
		SELECT
			(id::integer + CASE WHEN id < 26 THEN 97 ELSE 24 END)::"char"::text AS character,
			id::bit(5)::text AS index
		FROM generate_series(0, 31) AS id
	)
	SELECT string_agg(c.index, '')::varbit
	FROM regexp_split_to_table(_base32, '') AS s
	JOIN chars2bits AS c ON (lower(s) = c.character);
$fn$;

COMMENT ON FUNCTION otp.base32_bin(text) IS
$$
# Base32 to Binary Converter

Converts a Base32 string to its binary representation.

### Param details
- `_base32` (text): Base32-encoded string.

### Returns
- `varbit`: Binary representation of the input.

### Examples
```sql
SELECT base32_bin('GEZDGNBV'); -- Returns binary bit string
```
$$;

DROP FUNCTION IF EXISTS otp.bin_hex(varbit) CASCADE;

CREATE FUNCTION otp.bin_hex(_bin varbit)
RETURNS text
LANGUAGE SQL
STRICT IMMUTABLE
AS $fn$
	SELECT string_agg(to_hex(substring(_bin::text FROM n FOR 4)::bit(4)::integer), '' ORDER BY n)
	FROM generate_series(1, length(_bin), 4) AS n;
$fn$;

COMMENT ON FUNCTION otp.bin_hex(varbit) IS
$$
# Binary to Hexadecimal Converter

Converts a binary string to its hexadecimal representation.

### Param details
- `_bin` (bit): Binary input string.

### Returns
- `text`: Hexadecimal representation.

### Examples
```sql
SELECT bin_hex('1010'::bit); -- Returns 'a'
```
$$;

DROP FUNCTION IF EXISTS otp.get_otp(text, integer, integer, integer, text, timestamptz) CASCADE;

CREATE FUNCTION otp.get_otp(
	_secret text,
	_counter integer = NULL,
	_period integer = 30,
	_length integer = 6,
	_algorithm text = 'sha1',
	_time timestamptz = CURRENT_TIMESTAMP)
RETURNS text
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
	_buffer varbit;
	_hmac text;
	_offset integer;
	_part1 integer;
BEGIN
	_counter := COALESCE(_counter, FLOOR(EXTRACT(EPOCH FROM _time) / _period)::integer);

	_secret := lower(_secret);

	IF _secret !~ '^[a-z2-7]+$'
	THEN
		RAISE EXCEPTION 'Data contains non-base32 characters';
	END IF;

	IF length(_secret) % 8 IN (1, 3, 8)
	THEN
		RAISE EXCEPTION 'Length of data invalid';
	END IF;

	_buffer := otp.base32_bin(_secret);

	IF _buffer::text !~ ('0{' || length(_buffer) % 8 || '}$')
	THEN
		RAISE EXCEPTION 'PADDING number of bits at the end of output buffer are not all zero';
	END IF;

	_hmac := encode(
		hmac(
			decode(lpad(to_hex(_counter), 16, '0'), 'hex'),
			decode(otp.bin_hex(_buffer), 'hex'),
			_algorithm),
		'hex');

	_offset := ('x' || right(_hmac, 1))::bit(4)::integer;
	_part1 := ('x' || substr(_hmac, _offset * 2 + 1, 8))::bit(32)::integer;

	RETURN lpad(right((_part1 & x'7fffffff'::integer)::text, _length), _length, '0');
END;
$fn$;

COMMENT ON FUNCTION otp.get_otp(text, integer, integer, integer, text, timestamptz) IS
$$
# OTP Generator

Generates a one-time password (OTP) using TOTP or HOTP algorithm.

### Param details
- `_secret` (text): Base32-encoded secret key.
- `_counter` (integer, optional): Counter for HOTP (NULL for TOTP).
- `_period` (integer): Time period for TOTP in seconds (default: 30).
- `_length` (integer): Length of the OTP (default: 6).
- `_algorithm` (text): Hash algorithm (default: 'sha1').
- `_time` (timestamptz): Timestamp for TOTP (default: CURRENT_TIMESTAMP).

### Returns
- `text`: Generated OTP.

### Examples
```sql
SELECT get_otp('GEZDGNBV'); -- Returns a 6-digit TOTP, e.g., '123456'
```
$$;

DROP FUNCTION IF EXISTS otp.check_otp(text, text, integer, integer, integer, text) CASCADE;

CREATE FUNCTION otp.check_otp(
	_otp text,
	_secret text,
	_counter integer = NULL,
	_period integer = 30,
	_length integer = 6,
	_algorithm text = 'sha1')
RETURNS boolean
LANGUAGE plpgsql
STABLE
AS $fn$
DECLARE
	_result boolean;
BEGIN
	_result := otp.get_otp(_secret, _counter, _period, _length, _algorithm) = _otp;

	IF NOT _result
	THEN
		IF _counter IS NULL -- TOTP
		THEN
			_result := otp.get_otp(_secret, _counter, _period, _length, _algorithm, CURRENT_TIMESTAMP - (_period || 'sec')::interval) = _otp;
		ELSE -- HOTP
			_result := otp.get_otp(_secret, _counter - 1, _period, _length, _algorithm) = _otp;
		END IF;
	END IF;

	RETURN _result;
END;
$fn$;

COMMENT ON FUNCTION otp.check_otp(text, text, integer, integer, integer, text) IS
$$
# OTP Verification Function

Verifies a one-time password (OTP) against a secret key for TOTP or HOTP.

### Param details
- `_otp` (text): OTP to verify.
- `_secret` (text): Base32-encoded secret key.
- `_counter` (integer, optional): Counter for HOTP (NULL for TOTP).
- `_period` (integer): Time period for TOTP in seconds (default: 30).
- `_length` (integer): Length of the OTP (default: 6).
- `_algorithm` (text): Hash algorithm (default: 'sha1').

### Returns
- `boolean`: True if OTP is valid, false otherwise.

### Examples
```sql
SELECT check_otp('123456', 'GEZDGNBV'); -- Returns true if OTP is valid
```
$$;

DROP TABLE IF EXISTS otp.secrets CASCADE;

CREATE TABLE otp.secrets (
	id text NOT NULL,
	secret text NOT NULL,
	type text NOT NULL CHECK (type IN ('totp', 'hotp')),
	counter integer,
	period integer NOT NULL DEFAULT 30,
	length integer NOT NULL DEFAULT 6,
	algorithm text NOT NULL DEFAULT 'sha1',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (id)
);

COMMENT ON TABLE otp.secrets IS
$$
# Secrets Table

Stores TOTP and HOTP secret keys with their settings for server-side verification.

### Columns
- `id` (text): Unique identifier for the secret.
- `secret` (text): Base32-encoded secret key.
- `type` (text): 'totp' or 'hotp'.
- `counter` (integer): Current counter (HOTP only, NULL for TOTP).
- `period` (integer): Time period in seconds (default: 30).
- `length` (integer): OTP length (default: 6).
- `algorithm` (text): Hash algorithm (default: 'sha1').
- `created_at` (timestamptz): Timestamp of registration.
- `updated_at` (timestamptz): Timestamp of last update.
$$;

DROP FUNCTION IF EXISTS otp.register_secret(text, text, text, integer, integer, integer, text) CASCADE;

CREATE FUNCTION otp.register_secret(
	_id text,
	_secret text,
	_type text,
	_counter integer = NULL,
	_period integer = 30,
	_length integer = 6,
	_algorithm text = 'sha1'
)
RETURNS void
LANGUAGE SQL
AS $fn$
	INSERT INTO otp.secrets (id, secret, type, counter, period, length, algorithm)
	VALUES (_id, _secret, _type, _counter, _period, _length, _algorithm);
$fn$;

COMMENT ON FUNCTION otp.register_secret(text, text, text, integer, integer, integer, text) IS
$$
# Register Secret

Registers a new TOTP or HOTP secret.

### Param details
- `_id` (text): Unique identifier for the secret.
- `_secret` (text): Base32-encoded secret key.
- `_type` (text): Secret type - 'totp' or 'hotp'.
- `_counter` (integer, optional): Initial counter for HOTP (default: NULL).
- `_period` (integer): Time period for TOTP in seconds (default: 30).
- `_length` (integer): OTP length (default: 6).
- `_algorithm` (text): Hash algorithm (default: 'sha1').

### Examples
```sql
SELECT register_secret('user@example.com', 'GEZDGNBV', 'totp');
SELECT register_secret('user@example.com', 'GEZDGNBV', 'hotp', _counter := 0);
```
$$;

DROP FUNCTION IF EXISTS otp.unregister_secret(text) CASCADE;

CREATE FUNCTION otp.unregister_secret(_id text)
RETURNS boolean
LANGUAGE SQL
STRICT
AS $fn$
	DELETE FROM otp.secrets WHERE id = _id
	RETURNING true;
$fn$;

COMMENT ON FUNCTION otp.unregister_secret(text) IS
$$
# Unregister Secret

Removes a secret by id.

### Param details
- `_id` (text): Unique identifier of the secret to remove.

### Returns
- `boolean`: True if a secret was removed, false otherwise.

### Examples
```sql
SELECT unregister_secret('user@example.com');
```
$$;

DROP FUNCTION IF EXISTS otp.get_secret(text) CASCADE;

CREATE FUNCTION otp.get_secret(_id text)
RETURNS TABLE (
	secret text,
	type text,
	counter integer,
	period integer,
	length integer,
	algorithm text,
	created_at timestamptz,
	updated_at timestamptz,
	seconds_remaining integer
)
LANGUAGE SQL
STRICT
STABLE
AS $fn$
	SELECT
		s.secret,
		s.type,
		s.counter,
		s.period,
		s.length,
		s.algorithm,
		s.created_at,
		s.updated_at,
		CASE WHEN s.type = 'totp'
			THEN (s.period - (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::integer % s.period))::integer
			ELSE NULL
		END
	FROM otp.secrets AS s
	WHERE s.id = _id;
$fn$;

COMMENT ON FUNCTION otp.get_secret(text) IS
$$
# Get Secret Info

Returns stored parameters for a secret, including seconds remaining for TOTP.

### Param details
- `_id` (text): Unique identifier of the secret.

### Returns
- `record`: Secret details, counter, period, length, algorithm, timestamps, and seconds_remaining.
$$;

DROP FUNCTION IF EXISTS otp.verify_hotp(text, text, integer) CASCADE;

CREATE FUNCTION otp.verify_hotp(
	_id text,
	_otp text,
	_window integer = 1)
RETURNS boolean
LANGUAGE plpgsql
STRICT
AS $fn$
DECLARE
	_secret text;
	_cur integer;
	_length integer;
	_algorithm text;
	_candidate text;
	_i integer := 0;
BEGIN
	SELECT s.secret, s.counter, s.length, s.algorithm
	INTO _secret, _cur, _length, _algorithm
	FROM otp.secrets AS s
	WHERE s.id = _id
	FOR UPDATE;

	IF NOT FOUND THEN
		RAISE EXCEPTION 'Secret not found: %', _id;
	END IF;

	LOOP
		_candidate := otp.get_otp(_secret, _cur + _i, _length := _length, _algorithm := _algorithm);

		IF _candidate = _otp THEN
			UPDATE otp.secrets
			SET counter = _cur + _i + 1, updated_at = now()
			WHERE id = _id;
			RETURN true;
		END IF;

		_i := _i + 1;
		EXIT WHEN _i > _window;
	END LOOP;

	RETURN false;
END;
$fn$;

COMMENT ON FUNCTION otp.verify_hotp(text, text, integer) IS
$$
# Verify HOTP with Stored Secret

Verifies a HOTP against a stored secret with look-ahead window.
On success, updates the counter atomically (row-locked).

### Param details
- `_id` (text): Unique identifier of the secret.
- `_otp` (text): OTP to verify.
- `_window` (integer): Look-ahead window size (default: 1).

### Returns
- `boolean`: True if OTP is valid and counter was updated.

### Examples
```sql
SELECT verify_hotp('user@example.com', '123456');
SELECT verify_hotp('user@example.com', '123456', _window := 3);
```
$$;

DROP FUNCTION IF EXISTS otp.verify_totp(text, text, integer) CASCADE;

CREATE FUNCTION otp.verify_totp(
	_id text,
	_otp text,
	_drift integer = 1)
RETURNS boolean
LANGUAGE plpgsql
STRICT
AS $fn$
DECLARE
	_secret text;
	_period integer;
	_length integer;
	_algorithm text;
	_cur_step integer;
	_i integer;
	_time timestamptz;
BEGIN
	SELECT s.secret, s.period, s.length, s.algorithm
	INTO _secret, _period, _length, _algorithm
	FROM otp.secrets AS s
	WHERE s.id = _id;

	IF NOT FOUND THEN
		RAISE EXCEPTION 'Secret not found: %', _id;
	END IF;

	_cur_step := FLOOR(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) / _period)::integer;

	FOR _i IN -_drift .. _drift LOOP
		_time := to_timestamp((_cur_step + _i) * _period);
		IF otp.get_otp(_secret, _period := _period, _length := _length, _algorithm := _algorithm, _time := _time) = _otp THEN
			UPDATE otp.secrets
			SET updated_at = now()
			WHERE id = _id;
			RETURN true;
		END IF;
	END LOOP;

	RETURN false;
END;
$fn$;

COMMENT ON FUNCTION otp.verify_totp(text, text, integer) IS
$$
# Verify TOTP with Stored Secret

Verifies a TOTP against a stored secret with configurable drift tolerance.

### Param details
- `_id` (text): Unique identifier of the secret.
- `_otp` (text): OTP to verify.
- `_drift` (integer): Number of periods to check before/after current (default: 1).

### Returns
- `boolean`: True if OTP is valid.

### Examples
```sql
SELECT verify_totp('user@example.com', '123456');
SELECT verify_totp('user@example.com', '123456', _drift := 2);
```
$$;

DROP FUNCTION IF EXISTS otp.setup_secret(text, text, text, integer, integer, integer, text) CASCADE;

CREATE FUNCTION otp.setup_secret(
	_id text,
	_issuer text,
	_type text,
	_counter integer = NULL,
	_period integer = 30,
	_length integer = 6,
	_algorithm text = 'sha1'
)
RETURNS text
LANGUAGE plpgsql
AS $fn$
DECLARE
	_secret text;
BEGIN
	_secret := otp.random_base32(16);
	PERFORM otp.register_secret(_id, _secret, _type, _counter, _period, _length, _algorithm);
	RETURN otp.get_otp_setting_uri(_id, _secret, _issuer, _counter := _counter, _period := _period, _algorithm := _algorithm);
END;
$fn$;

COMMENT ON FUNCTION otp.setup_secret(text, text, text, integer, integer, integer, text) IS
$$
# Setup Secret

Generates a random Base32 secret, registers it in the secrets table, and returns an otpauth URI.

### Param details
- `_id` (text): Unique identifier for the secret.
- `_issuer` (text): Issuer name for the OTP.
- `_type` (text): Secret type - 'totp' or 'hotp'.
- `_counter` (integer, optional): Initial counter for HOTP (default: NULL).
- `_period` (integer): Time period for TOTP in seconds (default: 30).
- `_length` (integer): OTP length (default: 6).
- `_algorithm` (text): Hash algorithm (default: 'sha1').

### Returns
- `text`: OTP authentication URI.

### Examples
```sql
SELECT setup_secret('user@example.com', 'MyApp', 'totp');
-- Returns 'otpauth://totp/user%40example.com?secret=...&issuer=MyApp&period=30'

SELECT setup_secret('user@example.com', 'MyApp', 'hotp', _counter := 0);
-- Returns 'otpauth://hotp/user%40example.com?secret=...&issuer=MyApp&counter=0'
```
$$;

ALTER TABLE otp.secrets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS secrets_owner ON otp.secrets;
CREATE POLICY secrets_owner ON otp.secrets
	FOR ALL
	USING (id = current_user);

COMMENT ON POLICY secrets_owner ON otp.secrets IS
$$
# Row-Level Security

Users can only see/update their own row in the secrets table (WHERE id = current_user).
$$;

DROP FUNCTION IF EXISTS otp.enroll(jsonb) CASCADE;

CREATE FUNCTION otp.enroll(_params jsonb)
RETURNS json
LANGUAGE plpgsql
AS $fn$
DECLARE
	_issuer text := _params->>'issuer';
	_type text := COALESCE(_params->>'type', 'totp');
	_period integer := COALESCE((_params->>'period')::integer, 30);
	_length integer := COALESCE((_params->>'length')::integer, 6);
	_algorithm text := COALESCE(_params->>'algorithm', 'sha1');
	_secret text;
	_user_id text := current_user;
BEGIN
	IF _issuer IS NULL THEN
		RETURN json_build_object('error', 'issuer is required');
	END IF;

	_secret := otp.random_base32(16);
	INSERT INTO otp.secrets (id, secret, type, counter, period, length, algorithm)
	VALUES (
		_user_id, _secret, _type,
		CASE WHEN _type = 'hotp' THEN 0 ELSE NULL END,
		_period, _length, _algorithm
	);
	RETURN json_build_object(
		'enrolled', true,
		'type', _type,
		'uri', otp.get_otp_setting_uri(
			_user_id, _secret, _issuer,
			_counter := CASE WHEN _type = 'hotp' THEN 0 ELSE NULL END,
			_period := _period,
			_algorithm := _algorithm
		)
	);
END;
$fn$;

COMMENT ON FUNCTION otp.enroll(jsonb) IS 'Generates a random OTP secret for the current user and returns an enrollment URI.
--- PARAMS ---
{
  "issuer": "MyApp (required)",
  "type": "totp (default)",
  "period": 30,
  "length": 6,
  "algorithm": "sha1 (default)"
}';

DROP FUNCTION IF EXISTS otp.status(jsonb) CASCADE;

CREATE FUNCTION otp.status(_params jsonb DEFAULT '{}')
RETURNS json
LANGUAGE plpgsql
STABLE
AS $fn$
BEGIN
	RETURN json_build_object(
		'enabled', EXISTS (SELECT 1 FROM otp.secrets WHERE id = current_user)
	);
END;
$fn$;

COMMENT ON FUNCTION otp.status(jsonb) IS 'Returns whether the current user has OTP configured.
--- PARAMS ---
{}';

DROP FUNCTION IF EXISTS otp.disable(jsonb) CASCADE;

CREATE FUNCTION otp.disable(_params jsonb)
RETURNS json
LANGUAGE plpgsql
AS $fn$
DECLARE
	_otp text := _params->>'otp';
	_user_id text := current_user;
BEGIN
	IF _otp IS NULL THEN
		RETURN json_build_object('error', 'otp is required');
	END IF;

	IF otp.verify_totp(_user_id, _otp) THEN
		DELETE FROM otp.secrets WHERE id = _user_id;
		RETURN json_build_object('disabled', true);
	END IF;

	RETURN json_build_object('disabled', false, 'error', 'invalid OTP');
END;
$fn$;

COMMENT ON FUNCTION otp.disable(jsonb) IS 'Removes OTP for the current user after re-verification.
--- PARAMS ---
{
  "otp": "123456 (required)"
}';

DROP FUNCTION IF EXISTS otp.verify_login(jsonb) CASCADE;

CREATE FUNCTION otp.verify_login(_params jsonb)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
AS $fn$
DECLARE
	_user_id text := _params->>'user_id';
	_otp text := _params->>'otp';
	_secret text;
	_type text;
	_counter integer;
	_period integer;
	_length integer;
	_algorithm text;
	_cur_step integer;
	_i integer;
	_time timestamptz;
BEGIN
	IF _user_id IS NULL OR _otp IS NULL THEN
		RETURN json_build_object('valid', false, 'error', 'user_id and otp are required');
	END IF;

	SELECT s.secret, s.type, s.counter, s.period, s.length, s.algorithm
	INTO _secret, _type, _counter, _period, _length, _algorithm
	FROM otp.secrets AS s
	WHERE s.id = _user_id;

	IF NOT FOUND THEN
		RETURN json_build_object('valid', false);
	END IF;

	IF _type = 'hotp' THEN
		FOR _i IN 0 .. 1 LOOP
			IF otp.get_otp(_secret, _counter + _i, _length := _length, _algorithm := _algorithm) = _otp THEN
				UPDATE otp.secrets SET counter = _counter + _i + 1 WHERE id = _user_id;
				RETURN json_build_object('valid', true);
			END IF;
		END LOOP;
		RETURN json_build_object('valid', false);
	END IF;

	_cur_step := FLOOR(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) / _period)::integer;

	FOR _i IN -1 .. 1 LOOP
		_time := to_timestamp((_cur_step + _i) * _period);
		IF otp.get_otp(_secret, _period := _period, _length := _length, _algorithm := _algorithm, _time := _time) = _otp THEN
			RETURN json_build_object('valid', true);
		END IF;
	END LOOP;

	RETURN json_build_object('valid', false);
END;
$fn$;

COMMENT ON FUNCTION otp.verify_login(jsonb) IS 'Verifies an OTP code for a given user during login. Uses SECURITY DEFINER to read the secret for any user without authentication.
--- PARAMS ---
{
  "user_id": "alice@example.com (required)",
  "otp": "123456 (required)"
}';
