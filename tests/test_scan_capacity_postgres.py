"""Real PostgreSQL integration tests for global scan reservations.

The tests use a private schema per test and independent PostgreSQL connections,
so they exercise the same row locks and upserts used by separate API workers.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
import threading
import uuid

import psycopg
import pytest

from app import main


@pytest.fixture
def postgres_reservations(monkeypatch):
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("DATABASE_URL is required for PostgreSQL integration tests")

    schema = "sec13_" + uuid.uuid4().hex
    with psycopg.connect(database_url, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{schema}"')
    def connect():
        return psycopg.connect(database_url, options=f"-c search_path={schema}")
    try:
        with connect() as conn:
            conn.execute("""
                CREATE TABLE domains (
                    id BIGINT PRIMARY KEY,
                    domain TEXT NOT NULL UNIQUE
                )
            """)
            conn.execute("""
                CREATE TABLE scan_slots (
                    slot_id INTEGER PRIMARY KEY,
                    lease_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity'
                )
            """)
            conn.execute("""
                CREATE TABLE scan_rate_limits (
                    domain_id BIGINT PRIMARY KEY REFERENCES domains(id),
                    last_scan_started_at TIMESTAMPTZ NOT NULL
                )
            """)
            conn.cursor().executemany(
                "INSERT INTO scan_slots(slot_id) VALUES (%s)",
                [(slot,) for slot in range(1, main.MAX_CONCURRENT_SCANS + 1)],
            )
            conn.cursor().executemany(
                "INSERT INTO domains(id, domain) VALUES (%s, %s)",
                [(n, f"host{n}.example") for n in range(1, 21)],
            )
        monkeypatch.setattr(main, "db_connect", connect)
        yield connect
    finally:
        with psycopg.connect(database_url, autocommit=True) as admin:
            admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def test_concurrent_reservations_never_exceed_global_slot_count(postgres_reservations):
    workers = 12
    barrier = threading.Barrier(workers)

    def reserve(domain_id):
        barrier.wait(timeout=10)
        return main.reserve_scan_capacity(domain_id)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        reservations = list(pool.map(reserve, range(1, workers + 1)))

    granted = [slot for slot in reservations if slot is not None]
    assert len(granted) == main.MAX_CONCURRENT_SCANS
    assert len(set(granted)) == main.MAX_CONCURRENT_SCANS

    with ThreadPoolExecutor(max_workers=len(granted)) as pool:
        list(pool.map(main.release_scan_capacity, granted))


def test_same_domain_cooldown_is_atomic_across_concurrent_connections(postgres_reservations):
    workers = 10
    barrier = threading.Barrier(workers)

    def reserve(_):
        barrier.wait(timeout=10)
        slot = main.reserve_scan_capacity(1)
        if slot is not None:
            main.release_scan_capacity(slot)
        return slot

    with ThreadPoolExecutor(max_workers=workers) as pool:
        reservations = list(pool.map(reserve, range(workers)))

    assert sum(slot is not None for slot in reservations) == 1


def test_expired_worker_reservation_can_be_reclaimed(postgres_reservations):
    first = main.reserve_scan_capacity(1)
    assert first is not None

    with postgres_reservations() as conn:
        conn.execute(
            "UPDATE scan_slots SET lease_until=%s WHERE slot_id=%s",
            (datetime.now(timezone.utc) - timedelta(seconds=1), first),
        )

    second = main.reserve_scan_capacity(2)
    assert second == first
    main.release_scan_capacity(second)


def test_scan_deadline_is_strictly_inside_slot_lease():
    assert main.SCAN_EXECUTION_DEADLINE_SECONDS < main.SCAN_SLOT_LEASE_SECONDS
    assert main.SCAN_SLOT_LEASE_SECONDS - main.SCAN_EXECUTION_DEADLINE_SECONDS >= 30
