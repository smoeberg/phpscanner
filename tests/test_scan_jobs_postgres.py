"""PostgreSQL integration tests for persistent scan job claiming and completion."""
from datetime import datetime, timedelta, timezone
import os
import uuid

import psycopg
import pytest

from app import main, worker


@pytest.fixture
def postgres_jobs(monkeypatch):
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("DATABASE_URL is required for PostgreSQL integration tests")

    schema = "scan_jobs_" + uuid.uuid4().hex
    with psycopg.connect(database_url, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{schema}"')

    def connect():
        return psycopg.connect(database_url, options=f"-c search_path={schema}")

    try:
        with connect() as conn:
            conn.execute("""
                CREATE TABLE domains (
                    id BIGINT PRIMARY KEY,
                    domain TEXT NOT NULL UNIQUE,
                    verified_at TIMESTAMPTZ
                )
            """)
            conn.execute("""
                CREATE TABLE scans (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id BIGINT NOT NULL REFERENCES domains(id),
                    scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    status_code INTEGER,
                    final_url TEXT,
                    server_header TEXT,
                    powered_by TEXT,
                    php_indicator BOOLEAN NOT NULL DEFAULT false,
                    version_observed TEXT,
                    confidence TEXT NOT NULL DEFAULT 'unknown',
                    notes TEXT NOT NULL DEFAULT '',
                    job_id BIGINT UNIQUE
                )
            """)
            conn.execute("""
                CREATE TABLE scan_jobs (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id BIGINT NOT NULL REFERENCES domains(id),
                    status TEXT NOT NULL DEFAULT 'queued',
                    attempts INTEGER NOT NULL DEFAULT 0,
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
            conn.execute(
                "INSERT INTO domains(id, domain, verified_at) VALUES (1, 'example.com', now())"
            )
            conn.execute(
                "INSERT INTO scan_jobs(domain_id, status) VALUES (1, 'queued')"
            )
        monkeypatch.setattr(main, "db_connect", connect)
        yield connect
    finally:
        with psycopg.connect(database_url, autocommit=True) as admin:
            admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def test_claimed_job_can_be_reclaimed_after_worker_lease_expires(postgres_jobs):
    first = worker.claim_next_job()
    assert first is not None
    assert first[0] == 1
    assert first[2] == 1

    with postgres_jobs() as conn:
        conn.execute(
            "UPDATE scan_jobs SET lease_until = %s WHERE id = %s",
            (datetime.now(timezone.utc) - timedelta(seconds=1), first[0]),
        )

    second = worker.claim_next_job()
    assert second is not None
    assert second[0] == first[0]
    assert second[2] == 2
    assert second[3] != first[3]


def test_persist_result_completes_job_and_links_scan_once(postgres_jobs):
    claimed = worker.claim_next_job()
    assert claimed is not None
    job_id, domain_id, _attempts, token = claimed
    result = {
        "status_code": 200,
        "final_url": "https://example.com/",
        "server_header": "example",
        "powered_by": "",
        "php_indicator": False,
        "version_observed": None,
        "confidence": "unknown",
        "notes": "bounded observation",
    }

    worker.persist_result(job_id, domain_id, token, result)

    with postgres_jobs() as conn:
        job = conn.execute(
            "SELECT status, scan_id, lease_token FROM scan_jobs WHERE id = %s",
            (job_id,),
        ).fetchone()
        scans = conn.execute(
            "SELECT id, job_id, notes FROM scans WHERE job_id = %s",
            (job_id,),
        ).fetchall()

    assert job[0] == "succeeded"
    assert job[1] == scans[0][0]
    assert job[2] is None
    assert len(scans) == 1
    assert scans[0][1] == job_id
    assert scans[0][2] == "bounded observation"
