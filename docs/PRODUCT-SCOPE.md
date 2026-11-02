# Product scope: internal PHP exposure scanner

Status: proposed implementation scope. Merge approval required before implementation work proceeds.

## Product definition

The scanner is an internal tool operated by one authorized Inmente employee. Its purpose is to collect bounded, non-invasive HTTP(S) observations for explicitly authorized domains, derive carefully qualified maintenance/security findings, and export the resulting data as CSV for the sales team.

Sales is a downstream consumer of the CSV. Sales users do not need scanner accounts, a CRM, a dashboard, or an in-product lead-management workflow.

## Explicitly out of scope

- Multi-user administration, RBAC, tenant isolation, and external/customer accounts.
- CRM functionality, lead pipeline management, and sales activity tracking.
- PDF, HTML, or presentation report generation.
- Customer-facing portal or SaaS functionality.
- Automatic scanning of domains merely because they appear in prospect research.

## Required capabilities

1. Preserve the existing non-invasive scanner, DNS validation, pinned transport, rate limiting, lease/fencing behavior, domain verification, and CSV formula-injection protection.
2. Require a documented, valid authorization basis before any scan is started. Domain-control verification is not, by itself, proof of authorization to perform a security assessment.
3. Move scan execution out of the HTTP request lifecycle into persistent jobs with explicit status, bounded retries, timeout, and crash recovery.
4. Store raw observations separately from derived findings. Every finding must retain its evidence, source, confidence, and rationale.
5. Treat `undetermined` as a valid result. An externally observed PHP version or response header must never be represented as proof of a specific CVE or vulnerable package.
6. Provide a practical CSV export for sales. Keep spreadsheet formula-injection protection and make the export provenance clear.

## Minimal data concepts

- Prospect: an organization being researched; no login or user account.
- Domain: a hostname associated with a prospect, with association/ownership allowed to remain unverified.
- Authorization basis: who authorized the assessment, the scope/target, basis type, validity period, and a reference to supporting evidence.
- Scan target: the specific hostname and scope permitted by the authorization basis.
- Scan: one execution/job and its lifecycle.
- Observation: raw technical evidence collected by the scanner.
- Finding: a qualified interpretation of one or more observations.
- CSV export: a reproducible projection of scan/finding data for sales.

A domain being imported or verified must not automatically become authorized for scanning. Historical scans must be preserved and must not be assigned to a prospect or authorization basis by guesswork.

## Delivery sequence

1. **Foundation and data migration:** introduce versioned database migrations and add the minimal prospect/domain/authorization/target data model without deleting or guessing relationships for existing `domains` and `scans`.
2. **Authorization enforcement:** make scan initiation require a valid authorization basis for the exact target and scope; add negative tests.
3. **Persistent scan jobs:** separate API submission from execution; implement worker lifecycle, capacity control, retries, timeout, and recovery.
4. **Observations and findings:** persist structured evidence and derive findings with explicit confidence and rationale.
5. **CSV export:** produce stable, documented columns suitable for sales and preserve formula-injection protection.
6. **Operational hardening:** migrations in deployment, logging, health/readiness, backups, dependency/container review, and security/integration tests.

## Acceptance principles

- No scan starts without a current authorization basis covering its target.
- No destructive migration of existing domain or scan history.
- No inferred prospect ownership for historical data.
- A scan job remains inspectable after the initiating HTTP request ends.
- Findings are traceable to observations and do not overstate what remote evidence proves.
- Sales can consume the relevant results through CSV without needing access to the scanner.
