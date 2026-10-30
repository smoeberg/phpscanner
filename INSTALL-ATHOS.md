# DK PHP Exposure Scanner — Athos installation

This document describes deployment on the dedicated Athos environment.

The application is an MVP. It is not yet a production-ready national vulnerability scanner.

## 1. Environment configuration

Create .env only if it does not already exist:

    cp -n .env.example .env

Generate independent credentials:

    openssl rand -hex 32
    openssl rand -hex 32

Set the first value as POSTGRES_PASSWORD and the second as SCANNER_API_KEY in .env.

Protect the file:

    chmod 600 .env

Do not replace an existing production .env with the example file.

## 2. Validate configuration

    docker compose config --quiet

Do not continue if validation fails.

## 3. Build and deploy

For a new installation:

    docker compose up -d --build

For an existing production installation, deployment must follow an approved release and backup procedure. Do not run this command as an unreviewed upgrade.

## 4. Verify service status

    docker compose ps
    curl --fail http://127.0.0.1:8787/health

The API is bound to localhost on port 8787.

## 5. Access through SSH

On the workstation:

    ssh -L 8787:127.0.0.1:8787 root@YOUR_SERVER

Open:

    http://127.0.0.1:8787/docs

Administrative API requests require the X-API-Key header containing the configured SCANNER_API_KEY.

The /health endpoint does not require authentication.

## 6. Test with an authorized domain

Import a domain:

    curl -sS -X POST http://127.0.0.1:8787/domains/import \\
      -H 'Content-Type: application/json' \\
      -H 'X-API-Key: YOUR_SCANNER_API_KEY' \\
      -d '{"domains":["example.dk"],"source":"manual-test"}'

Only submit domains where you have an appropriate basis to perform the check.

## 7. Security limitations

Before any broader deployment, the following must be addressed:

- DNS rebinding and connection-level DNS pinning
- Header-only PHP version detection
- Explicit handling of blocked and rate-limited responses
- Robust network error classification
- Asynchronous DNS resolution
- Proper CSV streaming and formula-injection protection
- Authoritative PHP/vendor advisory data
- Automated tests and independent security review

The scanner does not prove that a website is vulnerable or patched. External observations must be kept separate from verified local runtime and package assessments.
