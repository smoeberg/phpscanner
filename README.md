# DK PHP Exposure Scanner

A non-invasive MVP for collecting HTTP(S) observations from explicitly
submitted domains. This project is not a CVE scanner and does not establish
whether a server is vulnerable.

## Architecture

- FastAPI application
- PostgreSQL database
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

## Scan rate limits

- At most 4 scans may hold a global database-backed capacity slot at once.
- A domain can start at most one scan every 60 seconds.
- Capacity slots and per-domain cooldown timestamps are stored in PostgreSQL, so the limits apply across API workers and replicas sharing the database.
- Slots use a 90-second lease and are released after the probe; a crashed worker's slot becomes available after lease expiry.
- A denied reservation returns HTTP 429. If PostgreSQL cannot enforce the reservation, the API fails closed with HTTP 503.
- The lease is a crash-recovery bound, not a hard execution timeout. Keep scan execution below 90 seconds; review this value if probe timeouts or scan behavior change.

## Authentication

All administrative API endpoints require the X-API-Key header.
The /health endpoint is public.

The API should remain accessible only through localhost and an SSH tunnel
until a separately reviewed public-access architecture is implemented.

## Installation

1. Create .env only if it does not already exist: `cp -n .env.example .env`.
2. Generate independent random values for POSTGRES_PASSWORD and
   SCANNER_API_KEY using openssl rand -hex 32.
3. Configure both values in .env.
4. Restrict access to .env using chmod 600 .env.
5. Validate and start the services:

   docker compose config --quiet
   docker compose up -d --build
   docker compose ps

6. Open an SSH tunnel:

   ssh -L 8787:127.0.0.1:8787 root@YOUR_SERVER

7. Open http://127.0.0.1:8787/docs.

Administrative API requests must include the X-API-Key header.

Never commit .env, database dumps, production data or API credentials.

## Current limitations

This is an MVP, not a production-ready national scanning platform.

Not yet implemented:

- Authoritative PHP/vendor advisory database
- CVE and distribution-specific package assessment
- Local read-only PHP runtime agent
- Background job queue and scheduling
- Comprehensive automated security and integration tests
- Full audit and authorization model for multiple users

No vulnerability conclusion should be derived solely from an externally
observed PHP version or response header.

## Development

See INSTALL-ATHOS.md for the Athos deployment procedure.
