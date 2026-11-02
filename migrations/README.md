# Database migrations

The application database schema is managed with Alembic. Run migrations with:

```sh
alembic upgrade head
```

The container entrypoint runs this command before starting the API.

## Existing installations

Revision `0001_core_entities` is deliberately idempotent for the existing scanner schema:

- Existing `domains`, `scans`, rate-limit rows and scan-slot state are retained.
- Missing legacy columns are added without replacing existing values.
- Existing scan history is not assigned to a prospect or authorization basis.
- New prospect and authorization tables start empty.
- Four capacity slots are inserted only when their slot IDs do not already exist.

Take a verified PostgreSQL backup before deploying any schema change. Test the migration against a recent copy of the production database before rollout.

## Authorization boundary

Domain-control TXT verification proves control of a DNS name for the challenge period; it is not equivalent to authorization to perform a security assessment. The new `authorization_bases` and `scan_targets` tables are the data foundation only. The scan endpoint is not yet enforced against these tables in this revision; that enforcement is the next implementation milestone and must be completed before using the expanded prospect workflow for scanning.

Historical scans intentionally remain associated only with their existing `domain_id`.
