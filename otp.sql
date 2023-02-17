
SET client_min_messages = warning;


CREATE FUNCTION random_base32(_length int = 16)
RETURNS text
LANGUAGE sql
STRICT IMMUTABLE
AS $$
  SELECT
    translate(string_agg((ceil(random() * 32 + 90))::int::"char", ''), '[\]^_`', '234567')
  FROM generate_series(1, _length);
$$;


CREATE FUNCTION url_encode(text)
RETURNS text
LANGUAGE sql
STRICT IMMUTABLE
AS $$
  SELECT string_agg(
    CASE WHEN ol > 1 OR ch !~ '[0-9a-zA-Z:/@._?#-]+'
      THEN regexp_replace(upper(substring(ch::bytea::text, 3)), '(..)', E'%\\1', 'g')
      ELSE ch
    END, '')
  FROM (
    SELECT ch, octet_length(ch) AS ol
    FROM regexp_split_to_table($1, '') AS ch
  ) AS s;
$$;


CREATE FUNCTION get_otp_setting_uri(_account_name text, _secret text, _issuer text, _counter int = NULL, _period int = NULL, _algorithm text = NULL, _url text = NULL)
RETURNS text
LANGUAGE sql
STRICT IMMUTABLE
AS $$
  SELECT concat(
    'otpauth://', CASE WHEN _counter IS NOT NULL THEN 'hotp' ELSE 'totp' END, '/', url_encode(_account_name),
    '?secret=', url_encode(_secret),
    '&issuer=' || url_encode(_issuer),
    '&counter=' || _counter,
    '&period=' || _period,
    '&algorithm=' || url_encode(_algorithm),
    '&url=' || url_encode(_url)
  );
$$;


CREATE FUNCTION base32_bin(_base32 text)
RETURNS "bit"
LANGUAGE sql
STRICT IMMUTABLE
AS $$
  WITH chars2bits AS (
    SELECT
      (id::int + CASE WHEN id < 26 THEN 97 ELSE 24 END)::"char"::text AS character,
      id::bit(5)::text AS index
    FROM generate_series(0, 31) AS id
  )
  SELECT string_agg(c.index, '')::"bit"
  FROM regexp_split_to_table(_base32, '') s
  JOIN chars2bits c ON (s = c.character);
$$;


CREATE FUNCTION bin_hex(_bin "bit")
RETURNS TEXT
LANGUAGE sql
STRICT IMMUTABLE
AS $$
  SELECT string_agg(h, '' ORDER BY n) FROM (
    SELECT substring(_bin::text FROM n FOR 4) AS b, n
    FROM generate_series(1, length(_bin), 4) n
    ) AS _b
  LEFT JOIN (
    SELECT
      (n::int + CASE WHEN n < 10 THEN 48 ELSE 87 END)::"char"::text AS h,
      n::bit(4)::text AS b
    FROM generate_series(0, 15) AS n
    ) AS _h
  USING (b);
$$;


CREATE FUNCTION get_otp(
  _secret text,
  _counter int = null,
  _period int = 30,
  _length int = 6,
  _algorithm text = 'sha1',
  _time timestamptz = current_timestamp)
RETURNS text
LANGUAGE plpgsql
STRICT IMMUTABLE
AS $$
DECLARE
  _buffer "bit";
  _hmac text;
  _offset int;
  _part1 int;
BEGIN
  _counter := coalesce(_counter, floor(extract(epoch FROM _time) / _period)::int);

  IF NOT _secret ~ '^[a-z2-7]+$' THEN
    RAISE EXCEPTION 'Data contains non-base32 characters';
  END IF;

  IF length(_secret) % 8 IN (1, 3, 8) THEN
    RAISE EXCEPTION 'Length of data invalid';
  END IF;

  _buffer := base32_bin(_secret);

  IF NOT _buffer ~ ('0{' || length(_buffer) % 8 || '}$') THEN
    RAISE EXCEPTION 'PADDING number of bits at the end of output buffer are not all zero';
  END IF;

  _hmac := encode(
    hmac(
      decode(lpad(to_hex(_counter), 16, '0'), 'hex'), -- counter / time
      decode(lpad(bin_hex(_buffer), 32, '0'), 'hex'), -- key
      _algorithm), -- default: sha1
    'hex');

  _offset := ('x' || lpad(substring(_hmac FROM '.$'), 8, '0'))::bit(32)::int;
  _part1 := ('x' || lpad(substring(_hmac, _offset * 2 + 1, 8), 8, '0'))::bit(32)::int;

  RETURN substring((_part1 & x'7fffffff'::int)::text FROM '.{' || _length || '}$');
END;
$$;


CREATE FUNCTION check_otp(
  _otp text,
  _secret text,
  _counter int = null,
  _period int = 30,
  _length int = 6,
  _algorithm text = 'sha1')
RETURNS bool
LANGUAGE plpgsql
STRICT IMMUTABLE
AS $$
DECLARE
  _result bool;
BEGIN
  _result := get_otp(_secret, _counter, _period, _length, _algorithm) = _otp;
  IF NOT _result THEN
    IF _counter IS NOT NULL THEN --HOTP
      _result := get_otp(_secret, _counter + 1, _period _length, _algorithm) = _otp;
      --TODO: update saved counter
    ELSE --TOTP
      _result := get_otp(_secret, _counter, _period, _length, _algorithm, current_timestamp - (_period || 'sec')::interval) = _otp;
    END IF;
  END IF;
  RETURN _result;
END;
$$;
