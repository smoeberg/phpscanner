#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="$(mktemp)"
OVERRIDE_FILE="$(mktemp)"
compose() {
  docker compose --project-name phpscanner-startup-smoke --env-file "$ENV_FILE" -f compose.yml -f "$OVERRIDE_FILE" "$@"
}

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "Compose startup verification failed; service logs follow:" >&2
    compose logs --no-color || true
  fi
  compose down --volumes --remove-orphans || true
  rm -f "$ENV_FILE" "$OVERRIDE_FILE"
  exit "$status"
}
trap cleanup EXIT

cat > "$ENV_FILE" <<'EOF'
POSTGRES_DB=php_scanner_smoke
POSTGRES_USER=smoke
POSTGRES_PASSWORD=smoke-only-password
SCANNER_API_KEY=smoke-only-api-key
EOF

cat > "$OVERRIDE_FILE" <<'EOF'
services:
  api:
    image: dk-php-scanner-api:startup-smoke
  worker:
    image: dk-php-scanner-api:startup-smoke
EOF

# Use a dedicated Compose project, volume, and image tag so local deployments are untouched.
compose down --volumes --remove-orphans
compose config --quiet
docker build --tag dk-php-scanner-api:startup-smoke .

compose up -d

wait_for_services() {
  local attempt
  for attempt in $(seq 1 60); do
    local services
    services="$(compose ps --format json)"
    if printf '%s' "$services" | jq -s -e 'any(.[]; .Service == "db" and .Health == "healthy")' >/dev/null \
      && printf '%s' "$services" | jq -s -e 'any(.[]; .Service == "api" and .Health == "healthy")' >/dev/null \
      && printf '%s' "$services" | jq -s -e 'any(.[]; .Service == "worker" and .State == "running")' >/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "Timed out waiting for healthy db/api and running worker" >&2
  compose ps
  return 1
}

wait_for_services

revision="$(compose exec -T db sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT version_num FROM alembic_version"')"
if [ "$revision" != "0004_scan_findings" ]; then
  echo "Expected Alembic head 0004_scan_findings, got: $revision" >&2
  exit 1
fi

table_count="$(compose exec -T db sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atq' <<'SQL'
SELECT count(*)
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
    'domains', 'scans', 'scan_rate_limits', 'scan_slots', 'prospects',
    'prospect_domains', 'authorization_bases', 'scan_targets', 'scan_jobs',
    'scan_observations', 'scan_findings', 'alembic_version'
  );
SQL
)"
if [ "$table_count" != "12" ]; then
  echo "Expected all 12 application/migration tables, found: $table_count" >&2
  exit 1
fi

# A container restart exercises the real entrypoint's repeated alembic upgrade.
compose restart api
wait_for_services

revision_after_restart="$(compose exec -T db sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT version_num FROM alembic_version"')"
if [ "$revision_after_restart" != "$revision" ]; then
  echo "Alembic revision changed after API restart: $revision_after_restart" >&2
  exit 1
fi

echo "Compose startup verified: fresh migrations, API readiness, worker startup, and restart idempotency."
