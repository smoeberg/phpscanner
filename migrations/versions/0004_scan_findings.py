"""Persist qualified findings separately from raw observations.

Revision ID: 0004_scan_findings
Revises: 0003_scan_observations
"""
from alembic import op

revision = "0004_scan_findings"
down_revision = "0003_scan_observations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE scan_findings (
            id BIGSERIAL PRIMARY KEY,
            scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            finding_type TEXT NOT NULL,
            assessment TEXT NOT NULL
                CHECK (assessment IN ('disclosed', 'possible', 'undetermined')),
            confidence TEXT NOT NULL
                CHECK (confidence IN ('high', 'low', 'undetermined')),
            version_observed TEXT,
            rationale TEXT NOT NULL,
            evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (scan_id, finding_type)
        )
    """)
    op.execute("""
        CREATE INDEX ix_scan_findings_scan_id
        ON scan_findings(scan_id, id)
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scan_findings_scan_id")
    op.execute("DROP TABLE IF EXISTS scan_findings")
