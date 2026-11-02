"""Create the legacy scanner schema if needed and add minimal prospect/authorization entities.

Revision ID: 0001_core_entities
Revises:
"""
from alembic import op

revision = "0001_core_entities"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Idempotent baseline: existing domains/scans and their rows are never dropped.
    op.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id BIGSERIAL PRIMARY KEY,
            domain TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL DEFAULT 'manual',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ")
    op.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS verification_token_hash TEXT")
    op.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS verification_expires_at TIMESTAMPTZ")

    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_rate_limits (
            domain_id BIGINT PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
            last_scan_started_at TIMESTAMPTZ NOT NULL
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_slots (
            slot_id INTEGER PRIMARY KEY,
            lease_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
            lease_token TEXT
        )
    """)
    op.execute("ALTER TABLE scan_slots ADD COLUMN IF NOT EXISTS lease_token TEXT")
    op.execute("""
        INSERT INTO scan_slots(slot_id)
        SELECT generate_series(1, 4)
        ON CONFLICT DO NOTHING
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id BIGSERIAL PRIMARY KEY,
            domain_id BIGINT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            status_code INTEGER,
            final_url TEXT,
            server_header TEXT,
            powered_by TEXT,
            php_indicator BOOLEAN NOT NULL DEFAULT false,
            version_observed TEXT,
            confidence TEXT NOT NULL DEFAULT 'unknown',
            notes TEXT NOT NULL DEFAULT ''
        )
    """)
    # Complete columns on databases created by earlier scanner revisions.
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS scanned_at TIMESTAMPTZ NOT NULL DEFAULT now()")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS status_code INTEGER")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS final_url TEXT")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS server_header TEXT")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS powered_by TEXT")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS php_indicator BOOLEAN NOT NULL DEFAULT false")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS version_observed TEXT")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS confidence TEXT NOT NULL DEFAULT 'unknown'")
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT ''")

    op.execute("""
        CREATE TABLE IF NOT EXISTS prospects (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            organization_number TEXT,
            website_url TEXT,
            notes TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS prospect_domains (
            id BIGSERIAL PRIMARY KEY,
            prospect_id BIGINT NOT NULL REFERENCES prospects(id) ON DELETE RESTRICT,
            domain_id BIGINT NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
            association_status TEXT NOT NULL DEFAULT 'unverified'
                CHECK (association_status IN ('unverified', 'verified', 'unknown')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (prospect_id, domain_id)
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS authorization_bases (
            id BIGSERIAL PRIMARY KEY,
            domain_id BIGINT NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
            basis_type TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            evidence_reference TEXT,
            granted_by TEXT NOT NULL,
            valid_from TIMESTAMPTZ NOT NULL,
            valid_until TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            revoked_at TIMESTAMPTZ,
            UNIQUE (id, domain_id),
            CHECK (valid_until IS NULL OR valid_until > valid_from)
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_targets (
            id BIGSERIAL PRIMARY KEY,
            domain_id BIGINT NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
            authorization_basis_id BIGINT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'disabled')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (domain_id, authorization_basis_id),
            FOREIGN KEY (authorization_basis_id, domain_id)
                REFERENCES authorization_bases(id, domain_id) ON DELETE RESTRICT
        )
    """)

    op.execute("CREATE INDEX IF NOT EXISTS ix_scans_scanned_at ON scans (scanned_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_scans_domain_scanned_at ON scans (domain_id, scanned_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_prospect_domains_domain_id ON prospect_domains (domain_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_authorization_bases_domain_validity ON authorization_bases (domain_id, valid_from, valid_until)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_scan_targets_domain_status ON scan_targets (domain_id, status)")


def downgrade() -> None:
    # Only remove entities introduced by this revision. Preserve legacy scanner data.
    op.execute("DROP TABLE IF EXISTS scan_targets")
    op.execute("DROP TABLE IF EXISTS prospect_domains")
    op.execute("DROP TABLE IF EXISTS authorization_bases")
    op.execute("DROP TABLE IF EXISTS prospects")
