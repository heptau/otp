-- PostgreSQL OTP Functions - Test Suite
-- No external dependencies required (pure SQL/PL/pgSQL)
--
-- Run: psql -U <user> -d <database> -f test/test.sql
-- Expected: All tests should pass (no ERROR/RAISE)

SET search_path = otp, public;

BEGIN;

-- url_encode
SELECT url_encode('user@example.com') AS url_encode_at;
SELECT url_encode('simple') AS url_encode_simple;

-- base32_bin / bin_hex roundtrip
SELECT bin_hex(base32_bin('GEZDGNBV')) AS base32_roundtrip;

-- random_base32 format validation
SELECT random_base32(16) AS rnd_b32;
SELECT length(random_base32(12)) = 12 AS rnd_b32_len;

-- get_otp_setting_uri
SELECT get_otp_setting_uri('user@example.com', 'GEZDGNBV', 'MyApp') AS uri_totp;
SELECT get_otp_setting_uri('user@example.com', 'GEZDGNBV', 'MyApp', _counter := 5) AS uri_hotp;
SELECT get_otp_setting_uri('user@example.com', 'GEZDGNBV', 'MyApp', _algorithm := 'sha256') AS uri_algorithm;

-- get_otp format and length
SELECT length(get_otp('GEZDGNBV', _counter := 0)) = 6 AS otp_len_6;
SELECT length(get_otp('GEZDGNBV', _counter := 0, _length := 8)) = 8 AS otp_len_8;

-- get_otp is deterministic for same inputs
SELECT get_otp('GEZDGNBV', _counter := 0) = get_otp('GEZDGNBV', _counter := 0) AS otp_deterministic;

-- check_otp valid and invalid
SELECT check_otp(get_otp('GEZDGNBV', _counter := 42), 'GEZDGNBV', _counter := 42) AS check_valid;
SELECT NOT check_otp('000000', 'GEZDGNBV', _counter := 42) AS check_invalid;

-- check_otp TOTP with one-step-back tolerance
SELECT check_otp(
   get_otp('GEZDGNBV', _time := CURRENT_TIMESTAMP - interval '30 seconds'),
   'GEZDGNBV'
) AS check_totp_tolerance;

-- check_otp HOTP with one-step-back tolerance
SELECT check_otp(
   get_otp('GEZDGNBV', _counter := 100),
   'GEZDGNBV',
   _counter := 101
) AS check_hotp_tolerance;

-- Error case: invalid Base32 characters
DO $$
BEGIN
   BEGIN
      PERFORM get_otp('88zzzzzz', _counter := 0);
      RAISE EXCEPTION 'FAIL: expected error for invalid Base32 chars';
   EXCEPTION
      WHEN OTHERS THEN
         IF SQLERRM LIKE '%non-base32%' THEN
            RAISE NOTICE 'PASS: invalid Base32 chars correctly rejected';
         ELSE
            RAISE EXCEPTION 'FAIL: unexpected error: %', SQLERRM;
         END IF;
   END;
END;
$$;

-- Error case: invalid Base32 length
DO $$
BEGIN
   BEGIN
      PERFORM get_otp('ABC', _counter := 0);
      RAISE EXCEPTION 'FAIL: expected error for invalid Base32 length';
   EXCEPTION
      WHEN OTHERS THEN
         IF SQLERRM LIKE '%Length%' THEN
            RAISE NOTICE 'PASS: invalid Base32 length correctly rejected';
         ELSE
            RAISE EXCEPTION 'FAIL: unexpected error: %', SQLERRM;
         END IF;
   END;
END;
$$;

-- Secrets table: register HOTP secret
SELECT register_secret('hotp@user', 'GEZDGNBV', 'hotp', _counter := 100) AS register_hotp;
SELECT counter = 100 AS hotp_counter_init FROM otp.get_secret('hotp@user');

-- Secrets table: verify HOTP with correct OTP
SELECT verify_hotp('hotp@user', get_otp('GEZDGNBV', _counter := 100, _algorithm := 'sha1')) AS hotp_verify_ok;
SELECT counter = 101 AS hotp_counter_after FROM otp.get_secret('hotp@user');

-- Secrets table: verify HOTP with wrong OTP
SELECT NOT verify_hotp('hotp@user', '000000') AS hotp_verify_wrong;
SELECT counter = 101 AS hotp_counter_unchanged FROM otp.get_secret('hotp@user');

-- Secrets table: verify HOTP with look-ahead (skip one counter)
SELECT verify_hotp('hotp@user', get_otp('GEZDGNBV', _counter := 104, _algorithm := 'sha1'), _window := 4) AS hotp_lookahead;
SELECT counter = 105 AS hotp_counter_lookahead FROM otp.get_secret('hotp@user');

-- Secrets table: register TOTP secret
SELECT register_secret('totp@user', 'GEZDGNBV', 'totp') AS register_totp;

-- Secrets table: verify TOTP with correct OTP
SELECT verify_totp('totp@user', otp.get_otp('GEZDGNBV', _algorithm := 'sha1')) AS totp_verify_ok;

-- Secrets table: verify TOTP with wrong OTP
SELECT NOT verify_totp('totp@user', '000000') AS totp_verify_wrong;

-- Secrets table: verify TOTP with drift tolerance
SELECT verify_totp('totp@user', otp.get_otp('GEZDGNBV', _time := CURRENT_TIMESTAMP - interval '30 seconds', _algorithm := 'sha1')) AS totp_verify_drift;

-- Secrets table: get_secret includes seconds_remaining for TOTP
SELECT seconds_remaining IS NOT NULL AS totp_has_remaining FROM otp.get_secret('totp@user');
SELECT seconds_remaining IS NULL AS hotp_no_remaining FROM otp.get_secret('hotp@user');

-- Secrets table: unregister both
SELECT unregister_secret('hotp@user') AS unregister_hotp;
SELECT unregister_secret('totp@user') AS unregister_totp;
SELECT get_secret('hotp@user') IS NULL AS hotp_gone;

-- setup_secret for TOTP
SELECT setup_secret('setup@user', 'TestApp', 'totp') AS setup_totp_uri;
SELECT type = 'totp' AS setup_type FROM otp.get_secret('setup@user');
SELECT seconds_remaining IS NOT NULL AS setup_remaining FROM otp.get_secret('setup@user');
SELECT unregister_secret('setup@user') AS cleanup_setup;

-- setup_secret for HOTP
SELECT setup_secret('setup@user', 'TestApp', 'hotp', _counter := 5) AS setup_hotp_uri;
SELECT type = 'hotp' AS setup_type FROM otp.get_secret('setup@user');
SELECT counter = 5 AS setup_counter FROM otp.get_secret('setup@user');
SELECT unregister_secret('setup@user') AS cleanup_setup;

-- Error: verify non-existent secret
DO $$
BEGIN
   BEGIN
      PERFORM verify_hotp('nonexistent', '000000');
      RAISE EXCEPTION 'FAIL: expected error for nonexistent secret';
   EXCEPTION
      WHEN OTHERS THEN
         IF SQLERRM LIKE '%not found%' THEN
            RAISE NOTICE 'PASS: nonexistent secret correctly rejected';
         ELSE
            RAISE EXCEPTION 'FAIL: unexpected error: %', SQLERRM;
         END IF;
   END;
END;
$$;

-- PgArachne integration: status before enroll
SELECT status('{}')->>'enabled' = 'false' AS status_before_enroll;

-- PgArachne integration: enroll current user
SELECT enroll('{"issuer": "TestApp"}')->>'uri' IS NOT NULL AS enroll_has_uri;
SELECT status('{}')->>'enabled' = 'true' AS status_after_enroll;

-- PgArachne integration: verify_login works
SELECT verify_login(jsonb_build_object(
   'user_id', current_user,
   'otp', otp.get_otp((SELECT secret FROM otp.secrets WHERE id = current_user))
))->>'valid' = 'true' AS verify_login_ok;

-- PgArachne integration: verify_login returns false for wrong OTP
SELECT verify_login(jsonb_build_object(
   'user_id', current_user, 'otp', '000000'
))->>'valid' = 'false' AS verify_login_bad;

-- PgArachne integration: verify_login returns false for unknown user
SELECT verify_login('{"user_id": "unknown_user", "otp": "000000"}')->>'valid' = 'false' AS verify_login_nouser;

-- PgArachne integration: disable with wrong OTP
SELECT disable('{"otp": "000000"}')->>'disabled' = 'false' AS disable_wrong;
SELECT status('{}')->>'enabled' = 'true' AS status_after_wrong_disable;

-- PgArachne integration: disable with correct OTP
SELECT disable(jsonb_build_object(
   'otp', otp.get_otp((SELECT secret FROM otp.secrets WHERE id = current_user))
))->>'disabled' = 'true' AS disable_ok;
SELECT status('{}')->>'enabled' = 'false' AS status_after_disable;

ROLLBACK;
