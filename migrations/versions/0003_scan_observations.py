"""Persist raw HTTP observations separately from scan summaries.

Revision ID: 0003_scan_observations
Revises: 0002_scan_jobs
"""
from alembic import op

revision = "0003_scan_observations"
down_revision = "0002_scan_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE scan_observations (
            id BIGSERIAL PRIMARY KEY,
            scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            observation_type TEXT NOT NULL
                CHECK (observation_type IN ('http_status', 'server_header', 'x_powered_by')),
            observed_value TEXT NOT NULL,
            source TEXT NOT NULL,
            observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            UNIQUE (scan_id, observation_type)
        )
    """)
    op.execute("""
        CREATE INDEX ix_scan_observations_scan_id
        ON scan_observations(scan_id, id)
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scan_observations_scan_id")
    op.execute("DROP TABLE IF EXISTS scan_observations")
