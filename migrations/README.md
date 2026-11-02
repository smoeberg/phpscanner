# Database migrations

The application database schema is managed with Alembic. Run migrations with:

```sh
alembic upgrade head
```

The API container runs this command before starting FastAPI. Compose waits for the API health check before starting the worker, avoiding concurrent migration attempts.

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

The protected operator API now supports creating and listing authorization records, disabling/re-enabling scan targets, and permanently revoking an authorization basis. Every action requires the scanner API key. The operator must retain a reference to the actual permission evidence; DNS verification must never be used as a substitute.

Historical scans intentionally remain associated only with their existing `domain_id`.


## Persistent scan jobs

Revision `0002_scan_jobs` adds a durable queue without rewriting historical scan rows. Scan submissions create a queued job; a separate worker claims it with `FOR UPDATE SKIP LOCKED`, an expiring lease, and a fencing token. Expired running jobs can be reclaimed after a worker crash. A scan result is linked to its job with a unique nullable `scans.job_id`; existing scans retain NULL and remain unchanged. The worker rechecks domain verification and the current authorization before each execution. Failed transient attempts are bounded, and successful result persistence is idempotent per job.

## Structured scan observations

Revision `0003_scan_observations` adds a child table for raw HTTP response observations. Each scan may store its response status, `Server` header, and `X-Powered-By` header independently, with a source identifier and observation timestamp. The unique scan/type constraint makes worker retries idempotent. Existing scan rows are preserved and receive no inferred observations. Response bodies are not stored.


## Derived scan findings

Revision `0004_scan_findings` stores one conservative PHP disclosure assessment per scan, separately from raw observations. Findings retain their assessment, confidence, rationale, observed version when explicitly disclosed, and references to the source observation rows. The initial rule set reports explicit `X-Powered-By: PHP` disclosure, treats a PHP string in `Server` as a low-confidence possible indicator, and otherwise reports `undetermined`. It never treats missing headers as proof PHP is absent or a disclosed version as proof of a vulnerability. Existing scans are not backfilled.
