"""SEC-14 PostgreSQL integration tests for worker reservation cleanup.

These tests run the real worker lifecycle and capacity SQL against an isolated
PostgreSQL schema. Only the external HTTP probe is controlled by the test.
"""
import asyncio

import pytest

from app import main, worker
from test_scan_capacity_postgres import postgres_reservations


@pytest.fixture
def lifecycle_database(postgres_reservations):
    connect = postgres_reservations
    with connect() as conn:
        conn.execute("UPDATE domains SET verified_at = now()")
        conn.execute(
            """
            CREATE TABLE scan_jobs (
                id BIGSERIAL PRIMARY KEY,
                domain_id BIGINT NOT NULL REFERENCES domains(id),
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 1,
                available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                lease_until TIMESTAMPTZ,
                lease_token TEXT,
                finished_at TIMESTAMPTZ,
                last_error TEXT,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    return connect


def _running_job(connect, domain_id=1):
    token = f"job-lease-{domain_id}"
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO scan_jobs(domain_id, status, attempts, lease_until, lease_token)
            VALUES (%s, 'running', 1, now() + interval '1 minute', %s)
            RETURNING id
            """,
            (domain_id, token),
        ).fetchone()
    return row[0], domain_id, 1, token


def _job_row(connect, job_id):
    with connect() as conn:
        return conn.execute(
            """
            SELECT status, attempts, lease_until, lease_token, last_error, finished_at
            FROM scan_jobs WHERE id = %s
            """,
            (job_id,),
        ).fetchone()


def _slot_row(connect, slot_id):
    with connect() as conn:
        return conn.execute(
            "SELECT lease_until > now(), lease_token FROM scan_slots WHERE slot_id = %s",
            (slot_id,),
        ).fetchone()


def _track_release(monkeypatch):
    released = []
    real_release = main.release_scan_capacity

    def release(slot_id, lease_token):
        released.append((slot_id, lease_token))
        return real_release(slot_id, lease_token)

    monkeypatch.setattr(main, "release_scan_capacity", release)
    return released


def test_timeout_releases_real_postgres_reservation_and_allows_next_scan(
    monkeypatch, lifecycle_database
):
    connect = lifecycle_database
    job = _running_job(connect)
    released = _track_release(monkeypatch)

    async def slow_probe(_domain):
        await asyncio.sleep(0.05)

    monkeypatch.setattr(main, "probe", slow_probe)
    monkeypatch.setattr(main, "SCAN_EXECUTION_DEADLINE_SECONDS", 0.001)

    asyncio.run(worker.process_job(job))

    job_row = _job_row(connect, job[0])
    assert job_row[0] == "queued"
    assert job_row[1] == 1
    assert job_row[2] is None
    assert job_row[3] is None
    assert job_row[4] == "Scan execution deadline exceeded"
    assert job_row[5] is None

    assert len(released) == 1
    slot_id, token = released[0]
    assert token
    assert _slot_row(connect, slot_id) == (False, None)
    assert main.reserve_scan_capacity(2) is not None


def test_probe_exception_releases_real_postgres_reservation(
    monkeypatch, lifecycle_database
):
    connect = lifecycle_database
    job = _running_job(connect)
    released = _track_release(monkeypatch)

    async def failing_probe(_domain):
        raise RuntimeError("controlled probe failure")

    monkeypatch.setattr(main, "probe", failing_probe)

    asyncio.run(worker.process_job(job))

    job_row = _job_row(connect, job[0])
    assert job_row[0] == "queued"
    assert job_row[4] == "Scan execution failed; see worker logs"
    assert len(released) == 1
    assert _slot_row(connect, released[0][0]) == (False, None)
    assert main.reserve_scan_capacity(2) is not None


def test_task_cancellation_releases_real_postgres_reservation(
    monkeypatch, lifecycle_database
):
    connect = lifecycle_database
    job = _running_job(connect)
    released = _track_release(monkeypatch)
    started = asyncio.Event()

    async def blocked_probe(_domain):
        started.set()
        await asyncio.Event().wait()

    async def run_and_cancel():
        monkeypatch.setattr(main, "probe", blocked_probe)
        task = asyncio.create_task(worker.process_job(job))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run_and_cancel())

    assert len(released) == 1
    assert _slot_row(connect, released[0][0])[1] is None
    # Cancellation leaves the claimed job for lease-based worker recovery.
    assert _job_row(connect, job[0])[0] == "running"
    assert main.reserve_scan_capacity(2) is not None


def test_cleanup_failure_preserves_timeout_and_keeps_lease_occupied(
    monkeypatch, lifecycle_database
):
    connect = lifecycle_database
    job = _running_job(connect)
    attempted_releases = []

    async def slow_probe(_domain):
        await asyncio.sleep(0.05)

    def failing_release(slot_id, lease_token):
        attempted_releases.append((slot_id, lease_token))
        raise RuntimeError("controlled database cleanup failure")

    monkeypatch.setattr(main, "probe", slow_probe)
    monkeypatch.setattr(main, "SCAN_EXECUTION_DEADLINE_SECONDS", 0.001)
    monkeypatch.setattr(main, "release_scan_capacity", failing_release)

    # Cleanup failure is logged and must not escape or replace the timeout.
    asyncio.run(worker.process_job(job))

    job_row = _job_row(connect, job[0])
    assert job_row[0] == "queued"
    assert job_row[4] == "Scan execution deadline exceeded"
    assert len(attempted_releases) == 1
    slot_id, token = attempted_releases[0]
    lease_active, current_token = _slot_row(connect, slot_id)
    assert lease_active is True
    assert current_token == token
