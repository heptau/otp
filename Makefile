PGDATABASE ?= otp_test
PGUSER ?= $(shell whoami)
PSQL ?= psql

SQL_FILE = otp.sql
TEST_DIR = test

all: help

install:
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -f $(SQL_FILE)

uninstall:
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.random_base32(integer) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.url_encode(text) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.get_otp_setting_uri(text, text, text, integer, integer, text) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.base32_bin(text) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.bin_hex(varbit) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.get_otp(text, integer, integer, integer, text, timestamptz) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.check_otp(text, text, integer, integer, integer, text) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.register_secret(text, text, text, integer, integer, integer, text) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.unregister_secret(text) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.get_secret(text) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.verify_hotp(text, text, integer) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.verify_totp(text, text, integer) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.setup_secret(text, text, text, integer, integer, integer, text) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.enroll(jsonb) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.status(jsonb) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.disable(jsonb) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP FUNCTION IF EXISTS otp.verify_login(jsonb) CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP TABLE IF EXISTS otp.secrets CASCADE;"
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "DROP SCHEMA IF EXISTS otp CASCADE;"

test: install
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -f $(TEST_DIR)/test.sql

setup-db:
	createdb -U $(PGUSER) $(PGDATABASE) || true
	$(PSQL) -U $(PGUSER) -d $(PGDATABASE) -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"

drop-db:
	dropdb -U $(PGUSER) $(PGDATABASE) || true

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  install     Install OTP functions into database (\$$PGDATABASE)"
	@echo "  uninstall   Remove all OTP functions, table, and schema"
	@echo "  test        Install and run test suite"
	@echo "  setup-db    Create test database and enable pgcrypto"
	@echo "  drop-db     Drop test database"
	@echo "  ci          setup-db + test + drop-db (for CI)"
	@echo "  help        Show this help"

ci: setup-db test drop-db

.PHONY: all install uninstall test setup-db drop-db ci help
