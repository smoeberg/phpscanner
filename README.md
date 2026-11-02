# DK PHP Exposure Scanner

A non-invasive MVP for collecting HTTP(S) observations from explicitly
submitted domains. This project is not a CVE scanner and does not establish
whether a server is vulnerable.

## Architecture

- FastAPI application
- PostgreSQL database-backed scan queue and separate worker
- Docker Compose deployment
- API key authentication using X-API-Key
- Host API binding restricted to 127.0.0.1:8787
- Explicit domain import and individually initiated scans

## Safety model

- Only scans explicitly imported domains.
- Makes ordinary HTTP(S) GET requests.
- Redirect following is disabled.
- TLS certificate verification is enabled.
- Rejects destinations resolving to non-public IP addresses.
- No exploit payloads, port scanning, crawling, brute force or exploitation.
- PHP/version observations are indicators, not proof of vulnerability.
- Does not modify Apache, firewalls, existing containers or databases.

DNS answers are validated and the TCP connection is pinned to an approved public IP. This remains defense in depth, not a complete egress security boundary.

## Prospect and domain management

All endpoints below require the `X-API-Key` header. Create a prospect with
`POST /prospects` using a required `name` and optional
`organization_number`, `website_url`, and `notes`. List prospects and their
associated domains with `GET /prospects`; optional `limit`, `offset`, and
`q` parameters provide bounded pagination and name/organization-number
filtering.

Associate an already imported domain using
`POST /prospects/{prospect_id}/domains` with a `domain_id`. The association
is created as `unverified` and repeated requests for the same pair are
idempotent. This is only an organizational link: it does not verify ownership,
change domain DNS verification, create an authorization basis, or permit a
scan. Historical scans remain attached only to their existing domain records.

## Authorization workflow

Domain TXT verification proves DNS control only; it is not permission to scan.
Before scanning, the operator must record an explicit authorization basis for
the exact domain. All endpoints below require the `X-API-Key` header.

- `POST /domains/{domain_id}/authorizations` records the basis and creates an
  active scan target. Required fields: `basis_type` (`written_permission`,
  `contract`, or `other`), `evidence_reference`, and `granted_by`. Optional
  fields: `description`, `valid_from` (timezone-aware ISO 8601; defaults to
  now), and `valid_until`.
- `GET /domains/{domain_id}/authorizations` lists the domain's authorization
  records and whether each is currently valid and enabled.
- `PATCH /scan-targets/{target_id}` accepts `{"status":"disabled"}` or
  `{"status":"active"}` to disable or re-enable a target.
- `POST /authorizations/{authorization_id}/revoke` permanently records
  revocation. A revoked basis cannot be reactivated; create a new authorization
  record if new permission is granted.

Creating an authorization does not bypass the separate domain TXT verification
requirement. A scan requires both a verified domain and a currently valid,
non-revoked authorization with an active scan target. Keep the evidence
reference tied to the actual written permission or contract; never treat DNS
verification or mere domain ownership as permission to scan.

Example request:

```sh
curl -X POST http://127.0.0.1:8787/domains/1/authorizations \
  -H "X-API-Key: $SCANNER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "basis_type": "written_permission",
    "evidence_reference": "internal-ticket-SEC-1042",
    "granted_by": "Named security contact",
    "valid_from": "2026-11-02T09:00:00+01:00",
    "valid_until": "2026-12-02T09:00:00+01:00"
  }'
```

## Scan jobs

`POST /domains/{domain_id}/scan` validates domain verification and current authorization, then returns HTTP 202 with a persistent `job_id`. The request does not perform the network probe. Poll `GET /scan-jobs/{job_id}` to inspect `queued`, `running`, `succeeded`, or `failed` status and retrieve the resulting `scan_id`. Both endpoints require `X-API-Key`.

The worker runs separately from the API, claims jobs with PostgreSQL row locking, and uses expiring leases and fencing tokens. A worker crash leaves a recoverable job; transient execution failures are retried up to three attempts. Result persistence is idempotent per job, so recovery does not create duplicate scan rows. The worker rechecks domain verification and authorization immediately before execution. If no capacity slot is available, the job is returned to the queue without consuming an attempt.

Each completed scan also stores the raw HTTP response status, `Server` header, and `X-Powered-By` header as separate observations linked to the scan. Retrieve them with the API-key-protected `GET /scans/{scan_id}/observations` endpoint. Response bodies are discarded and are not persisted. These observations are evidence only; they do not by themselves establish a vulnerability or CVE.

The worker also derives one separate `php_runtime_disclosure` finding per completed scan. Retrieve it with the API-key-protected `GET /scans/{scan_id}/findings` endpoint. An explicit `X-Powered-By: PHP` value is classified as a high-confidence technology disclosure; a PHP string in `Server` is only a low-confidence possible indicator. Otherwise the assessment is `undetermined`—not proof that PHP is absent. Each finding includes rationale and references to the raw observation IDs. A disclosed version is not classified as outdated or vulnerable without an authoritative advisory source.

The existing `/results.csv` export includes the finding assessment, confidence, disclosed version, rationale, and evidence JSON alongside the original scan columns. Historical scans are preserved and are not backfilled with inferred findings.

## Scan rate limits

- At most 4 scans may hold a global database-backed capacity slot at once.
- A domain can start at most one scan every 60 seconds.
- Capacity slots and per-domain cooldown timestamps are stored in PostgreSQL, so the limits apply across API workers and replicas sharing the database.
- Slots use a 90-second lease and are released after the probe; a crashed worker's slot becomes available after lease expiry.
- A job waits in the queue when no capacity slot or domain cooldown is available.
- Each probe has a strict 60-second deadline, leaving a 30-second lease safety margin.

## Operator interface

Open `http://127.0.0.1:8787/` through the documented SSH tunnel to use the
minimal single-operator browser interface. Enter the `SCANNER_API_KEY` when
prompted; the page keeps it in browser memory only and sends it as
`X-API-Key` for protected API requests. It is not stored in browser storage.

The interface supports prospect creation, domain import and association,
DNS TXT challenge/verification, authorization grant/list/revocation and
scan-target enable/disable, plus manual scan submission and job-status polling.
A domain association or DNS TXT verification is not scan permission. The API
continues to enforce a current authorization basis for the exact domain before
a scan job can be queued.

## Authentication

All administrative API endpoints require the X-API-Key header.
The `/health/live` endpoint is a public liveness check and does not depend on PostgreSQL. `/health/ready` is a public readiness check and returns HTTP 503 when PostgreSQL is unavailable. The legacy `/health` endpoint remains an alias for readiness. API request logs are emitted as JSON with a generated request ID, method, path, response status, and duration; query strings, request headers, and bodies are not logged. Uvicorn's duplicate access log is disabled. API and worker logs can be filtered with the `LOG_LEVEL` environment variable.

The API should remain accessible only through localhost and an SSH tunnel
until a separately reviewed public-access architecture is implemented.

## Installation

1. Create .env only if it does not already exist: `cp -n .env.example .env`.
2. Generate independent random values for POSTGRES_PASSWORD and
   SCANNER_API_KEY using openssl rand -hex 32.
3. Configure both values in .env.
4. Restrict access to .env using chmod 600 .env.
5. Validate and start the services:

   ```sh
   docker compose config --quiet
   docker compose up -d --build
   docker compose ps
   ```

   The API container runs `alembic upgrade head` before starting FastAPI and exposes a health check. Compose starts the separate worker only after the API is healthy, so the worker never races the schema migration.
   Back up PostgreSQL before deploying schema changes. See
   [migrations/README.md](migrations/README.md) for the migration policy.

6. Open an SSH tunnel:

   ```sh
   ssh -L 8787:127.0.0.1:8787 root@YOUR_SERVER
   ```

7. Open http://127.0.0.1:8787/docs.

Administrative API requests must include the X-API-Key header.

Never commit .env, database dumps, production data or API credentials.

## Current limitations

This is an MVP, not a production-ready national scanning platform.

Not yet implemented:

- Scheduled/recurring scans
- Authoritative PHP/vendor advisory database
- CVE and distribution-specific package assessment
- Local read-only PHP runtime agent
- Comprehensive automated security and integration tests
- Multi-user roles and a full multi-user audit model (out of scope for the single-operator MVP)

No vulnerability conclusion should be derived solely from an externally
observed PHP version or response header.

## Development

See INSTALL-ATHOS.md for the Athos deployment procedure.
