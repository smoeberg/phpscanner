"""Add durable scan jobs and link scan results to their originating job.

Revision ID: 0002_scan_jobs
Revises: 0001_core_entities
"""
from alembic import op

revision = "0002_scan_jobs"
down_revision = "0001_core_entities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE scan_jobs (
            id BIGSERIAL PRIMARY KEY,
            domain_id BIGINT NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
            status TEXT NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            started_at TIMESTAMPTZ,
            finished_at TIMESTAMPTZ,
            lease_until TIMESTAMPTZ,
            lease_token TEXT,
            scan_id BIGINT,
            last_error TEXT
        )
    """)
    op.execute("ALTER TABLE scans ADD COLUMN job_id BIGINT")
    op.execute("""
        ALTER TABLE scans ADD CONSTRAINT fk_scans_job_id
        FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE SET NULL
    """)
    op.execute("CREATE UNIQUE INDEX ux_scans_job_id ON scans(job_id) WHERE job_id IS NOT NULL")
    op.execute("""
        CREATE INDEX ix_scan_jobs_queue
        ON scan_jobs(status, available_at, created_at)
    """)
    op.execute("""
        CREATE INDEX ix_scan_jobs_domain_created
        ON scan_jobs(domain_id, created_at DESC)
    """)
    op.execute("""
        ALTER TABLE scan_jobs ADD CONSTRAINT fk_scan_jobs_scan_id
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scan_jobs_domain_created")
    op.execute("DROP INDEX IF EXISTS ix_scan_jobs_queue")
    op.execute("DROP INDEX IF EXISTS ux_scans_job_id")
    op.execute("ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS fk_scan_jobs_scan_id")
    op.execute("ALTER TABLE scans DROP CONSTRAINT IF EXISTS fk_scans_job_id")
    op.execute("ALTER TABLE scans DROP COLUMN IF EXISTS job_id")
    op.execute("DROP TABLE IF EXISTS scan_jobs")
