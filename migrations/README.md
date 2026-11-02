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

Domain-control TXT verification proves control of a DNS name for the challenge period; it is not equivalent to authorization to perform a security assessment. The new `authorization_bases` and `scan_targets` tables are the data foundation only. The scan endpoint now requires an active `scan_targets` row backed by a currently valid, non-revoked `authorization_bases` row for the exact domain. The check is performed in the same PostgreSQL transaction as scan-capacity reservation. Missing, future-dated, expired, revoked, or disabled authorization fails closed with HTTP 403. DNS TXT verification remains a separate domain-control check and is not accepted as scanning permission.

This milestone implements enforcement, not yet an operator-facing API for creating and revoking authorization records. Until that workflow is added, records must only be provisioned through a controlled administrative process; do not insert grants based solely on domain verification.

Historical scans intentionally remain associated only with their existing `domain_id`.
