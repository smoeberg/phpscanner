# DK PHP Exposure Scanner

Initial repository baseline for the Athos production MVP. The repository is the source of truth for reviewed development; production deployment remains a separate, approved operation.

The application is a non-invasive HTTP(S) observation service for explicitly submitted domains. It is not a CVE scanner and does not establish whether a server is vulnerable.

## Current baseline

- FastAPI and PostgreSQL
- Docker Compose deployment
- API key authentication for administrative endpoints
- API bound to localhost on Athos (`127.0.0.1:8787`)
- Redirect following disabled and TLS verification enabled
- DNS validation is present, but connection-level DNS pinning is not yet implemented

## Security and development status

This is an MVP, not a production-ready national scanning platform. Known limitations include DNS rebinding protection, authoritative PHP/vendor advisory data, local runtime assessment, automated security tests, rate limiting, and a complete authorization/audit model.

Never infer vulnerability or patch status solely from an externally observed PHP version or response header.

## Secrets and production data

Never commit `.env`, API credentials, database dumps, production data, backups, or private keys. Use `.env.example` only as a template.

See `INSTALL-ATHOS.md` for deployment guidance. Changes must be reviewed and tested before deployment to Athos.
