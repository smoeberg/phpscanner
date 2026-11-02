# PostgreSQL backup and restore runbook

This runbook covers a manual, operator-triggered backup and a restore drill for
the scanner's PostgreSQL database. It does not configure automated backups or
claim that a backup is valid until a restore has been tested.

## Before you start

- Run commands from the directory containing the production Compose file.
- Identify the PostgreSQL Compose service with `docker compose config --services`.
- Set `DB_SERVICE` to that exact service name. Do not assume the service is
  named `db` or `postgres`.
- Confirm that the database container has `pg_dump`, `pg_restore`,
  `createdb`, and `dropdb` available.
- Ensure the host has enough protected disk space for the dump.
- Never put database passwords in command-line arguments or commit backups to
  the repository.

The examples below expect the database container to provide
`POSTGRES_USER` and `POSTGRES_DB`, as in the standard PostgreSQL container
configuration used by Compose. If the deployment uses different environment
variable names or an external database, adapt the commands to that deployment
and its approved credential mechanism before running them.

## Create a backup

Choose a protected backup location on the host. The directory must not be
inside the repository and should be accessible only to the operator.

```sh
set -euo pipefail
umask 077

export DB_SERVICE='<postgres-compose-service>'
BACKUP_DIR='/var/backups/phpscanner'
BACKUP_FILE="$BACKUP_DIR/phpscanner-$(date -u +%Y%m%dT%H%M%SZ).dump"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

docker compose exec -T "$DB_SERVICE" sh -c \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner --no-acl' \
  > "$BACKUP_FILE"

test -s "$BACKUP_FILE"
sha256sum "$BACKUP_FILE" > "$BACKUP_FILE.sha256"
chmod 600 "$BACKUP_FILE" "$BACKUP_FILE.sha256"
```

Record the backup timestamp, checksum, source environment, and the software
version/commit deployed at the time of backup in the operator's approved
operational record. Do not put secrets or production data in GitHub issues or
pull requests.

## Verify the backup archive

A successful `pg_dump` exit is necessary but not sufficient. First verify that
the archive can be read:

```sh
set -euo pipefail
sha256sum --check "$BACKUP_FILE.sha256"
docker compose exec -T "$DB_SERVICE" pg_restore --list - < "$BACKUP_FILE" >/dev/null
```

This checks the checksum and archive directory only. It does not prove that the
database can be restored or that the application works against the restored
data. Perform the restore drill below.

## Restore drill into a separate database

Run this on a non-production environment or an explicitly approved isolated
database instance. The restore target must be a new, empty database. Do not
point this procedure at the live application database.

```sh
set -euo pipefail

export DB_SERVICE='<postgres-compose-service>'
export RESTORE_DB='phpscanner_restore_drill'

# Confirm the target name is not the configured application database.
APP_DB="$(docker compose exec -T "$DB_SERVICE" sh -c 'printf %s "$POSTGRES_DB"')"
test "$RESTORE_DB" != "$APP_DB"

# The command fails rather than silently reusing an existing database.
docker compose exec -T "$DB_SERVICE" sh -c \
  'createdb -U "$POSTGRES_USER" "$1"' sh "$RESTORE_DB"

docker compose exec -T "$DB_SERVICE" sh -c \
  'pg_restore -U "$POSTGRES_USER" -d "$1" --no-owner --no-acl' \
  sh "$RESTORE_DB" < "$BACKUP_FILE"

# Confirm PostgreSQL can connect and the restored schema contains tables.
docker compose exec -T "$DB_SERVICE" sh -c \
  'psql -U "$POSTGRES_USER" -d "$1" -v ON_ERROR_STOP=1 -c "\dt"' \
  sh "$RESTORE_DB"
```

After the restore, validate the expected Alembic revision and run the
application's read-only health and representative API checks against the
isolated restored database. Do not start a worker pointed at a restored copy
unless the environment is isolated from production targets and outbound
scanning is disabled. A restore drill must never trigger scans.

When the drill is complete, remove only the dedicated drill database:

```sh
docker compose exec -T "$DB_SERVICE" sh -c \
  'dropdb -U "$POSTGRES_USER" --if-exists "$1"' sh "$RESTORE_DB"
```

## Production recovery

Production recovery is a separate, explicitly approved operation. Before
restoring:

1. Confirm the incident, target environment, backup timestamp, and checksum.
2. Stop the API and worker so no process writes to the database.
3. Preserve a separate backup of the current database before replacing it.
4. Confirm the restore target database name and credentials independently.
5. Restore using the deployment's approved PostgreSQL recovery procedure.
6. Run `alembic upgrade head` if the restored database is behind the deployed
   application revision; do not downgrade automatically.
7. Start the API, verify health and logs, then start the worker.
8. Confirm existing domains, scan history, authorizations, jobs, observations,
   and findings are present and internally consistent.
9. Record the recovery point, recovery time, backup used, checks performed,
   and any data loss.

Do not run destructive `dropdb`, `pg_restore --clean`, or volume-removal
commands against production as part of this runbook without a separately
reviewed recovery plan.

## Operational policy

- Backups contain sensitive operational data. Encrypt them at rest and in
  transit using the organization's approved storage process.
- Restrict access to backups and retain them according to the organization's
  retention policy.
- Store backup copies separately from the database host; a local dump alone
  does not protect against host or volume loss.
- Schedule backups and restore drills through the organization's operational
  process. This document does not create a schedule or guarantee off-host
  replication.
- Test a restore after PostgreSQL major-version changes and before relying on
  a new backup/restore method.

## Automated isolated restore drill

The CI workflow runs `scripts/verify-postgres-restore.sh` against its disposable
PostgreSQL 16 service. The script creates uniquely named source and restore
databases, applies the repository's Alembic migrations to the source, inserts
non-sensitive fixture records, creates a custom-format `pg_dump`, verifies its
SHA-256 checksum and archive directory, and restores it into the separate empty
target database. It then checks the restored Alembic revision, all 12 expected
application/migration tables, and the fixture domain/prospect association.
Both databases and the temporary dump are removed on exit.

This CI check validates the backup/restore mechanics and current schema against
synthetic data. It is **not** a restore of a production backup and does not
establish that any particular operational backup is recoverable. Operators must
still perform the isolated restore drill above using an actual protected backup,
then validate the restored application data and record the result. The CI job
never receives production credentials or backup files.
