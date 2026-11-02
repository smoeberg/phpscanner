#!/usr/bin/env bash
set -Eeuo pipefail

: "${PGHOST:?Set PGHOST to an isolated PostgreSQL test service}"
: "${PGPORT:?Set PGPORT}"
: "${PGUSER:?Set PGUSER}"
: "${PGPASSWORD:?Set PGPASSWORD}"

# The script creates and drops only these uniquely named databases. It never
# accepts a caller-supplied database name and must run against an isolated DB.
DRILL_ID="$(python -c 'import uuid; print(uuid.uuid4().hex[:12])')"
SOURCE_DB="phpscanner_restore_source_${DRILL_ID}"
RESTORE_DB="phpscanner_restore_target_${DRILL_ID}"
TMP_DIR="$(mktemp -d)"
SOURCE_CREATED=0
RESTORE_CREATED=0

export PGDATABASE=postgres

cleanup() {
  status=$?
  set +e
  if [ "$RESTORE_CREATED" -eq 1 ]; then
    dropdb --if-exists --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" "$RESTORE_DB"
  fi
  if [ "$SOURCE_CREATED" -eq 1 ]; then
    dropdb --if-exists --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" "$SOURCE_DB"
  fi
  rm -rf "$TMP_DIR"
  exit "$status"
}
trap cleanup EXIT

createdb --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" "$SOURCE_DB"
SOURCE_CREATED=1
createdb --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" "$RESTORE_DB"
RESTORE_CREATED=1

# Exercise the repository's actual Alembic migrations in a disposable database.
export DATABASE_URL="$(python -c 'import os; from urllib.parse import quote; print("postgresql://" + quote(os.environ["PGUSER"], safe="") + ":" + quote(os.environ["PGPASSWORD"], safe="") + "@" + os.environ["PGHOST"] + ":" + os.environ["PGPORT"] + "/" + os.environ["SOURCE_DB"])')"
export SOURCE_DB
python -m alembic upgrade head

psql --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" --dbname "$SOURCE_DB" \
  --set ON_ERROR_STOP=1 <<'SQL'
WITH domain_row AS (
  INSERT INTO domains (domain, source)
  VALUES ('restore-drill.example', 'restore-drill')
  RETURNING id
),
prospect_row AS (
  INSERT INTO prospects (name, website_url, notes)
  VALUES ('Restore drill fixture', 'https://restore-drill.example', 'Disposable CI fixture')
  RETURNING id
)
INSERT INTO prospect_domains (prospect_id, domain_id)
SELECT prospect_row.id, domain_row.id
FROM prospect_row CROSS JOIN domain_row;
SQL

BACKUP_FILE="$TMP_DIR/phpscanner-restore-drill.dump"
pg_dump --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" \
  --format=custom --no-owner --no-acl --file "$BACKUP_FILE" "$SOURCE_DB"
test -s "$BACKUP_FILE"
sha256sum "$BACKUP_FILE" > "$BACKUP_FILE.sha256"
sha256sum --check "$BACKUP_FILE.sha256"
pg_restore --list "$BACKUP_FILE" > "$TMP_DIR/archive.list"
test -s "$TMP_DIR/archive.list"

# Restore to a different, empty database; fail on the first SQL error.
pg_restore --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" \
  --dbname "$RESTORE_DB" --exit-on-error --no-owner --no-acl "$BACKUP_FILE"

revision="$(psql --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" \
  --dbname "$RESTORE_DB" --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --command 'SELECT version_num FROM alembic_version')"
if [ "$revision" != "0004_scan_findings" ]; then
  echo "Unexpected restored Alembic revision: $revision" >&2
  exit 1
fi

table_count="$(psql --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" \
  --dbname "$RESTORE_DB" --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --command "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'")"
if [ "$table_count" != "12" ]; then
  echo "Expected 12 restored application/migration tables, found: $table_count" >&2
  exit 1
fi

domain_count="$(psql --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" \
  --dbname "$RESTORE_DB" --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --command "SELECT count(*) FROM domains WHERE domain = 'restore-drill.example' AND source = 'restore-drill'")"
prospect_count="$(psql --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" \
  --dbname "$RESTORE_DB" --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --command "SELECT count(*) FROM prospects WHERE name = 'Restore drill fixture'")"
association_count="$(psql --host "$PGHOST" --port "$PGPORT" --username "$PGUSER" \
  --dbname "$RESTORE_DB" --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --command 'SELECT count(*) FROM prospect_domains')"

if [ "$domain_count" != "1" ] || [ "$prospect_count" != "1" ] || [ "$association_count" != "1" ]; then
  echo "Restored fixture data did not match expected domain/prospect association" >&2
  exit 1
fi

echo "PostgreSQL restore drill passed: checksum, archive listing, Alembic revision, 12 tables, and fixture data verified."
