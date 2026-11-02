"""PostgreSQL integration tests for fail-closed scan authorization."""
from datetime import datetime, timedelta, timezone
import os
import uuid

import psycopg
import pytest

from app import main


@pytest.fixture
def authorization_db(monkeypatch):
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("DATABASE_URL is required for PostgreSQL integration tests")

    schema = "authz_" + uuid.uuid4().hex
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
                CREATE TABLE authorization_bases (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id BIGINT NOT NULL REFERENCES domains(id),
                    basis_type TEXT NOT NULL DEFAULT 'written_permission',
                    description TEXT NOT NULL DEFAULT '',
                    evidence_reference TEXT,
                    granted_by TEXT NOT NULL DEFAULT 'operator',
                    valid_from TIMESTAMPTZ NOT NULL,
                    valid_until TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    revoked_at TIMESTAMPTZ,
                    UNIQUE (id, domain_id),
                    CHECK (valid_until IS NULL OR valid_until > valid_from)
                )
            """)
            conn.execute("""
                CREATE TABLE scan_targets (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id BIGINT NOT NULL REFERENCES domains(id),
                    authorization_basis_id BIGINT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    UNIQUE (domain_id, authorization_basis_id),
                    FOREIGN KEY (authorization_basis_id, domain_id)
                        REFERENCES authorization_bases(id, domain_id)
                )
            """)
            conn.execute("""
                CREATE TABLE scan_slots (
                    slot_id INTEGER PRIMARY KEY,
                    lease_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
                    lease_token TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE scan_rate_limits (
                    domain_id BIGINT PRIMARY KEY REFERENCES domains(id),
                    last_scan_started_at TIMESTAMPTZ NOT NULL
                )
            """)
            conn.execute("INSERT INTO domains(id, domain) VALUES (1, 'authorized.example'), (2, 'other.example')")
            conn.execute("INSERT INTO scan_slots(slot_id) VALUES (1), (2), (3), (4)")
        monkeypatch.setattr(main, "db_connect", connect)
        yield connect
    finally:
        with psycopg.connect(database_url, autocommit=True) as admin:
            admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def _add_target(connect, *, domain_id=1, valid_from=None, valid_until=None, revoked_at=None, status="active"):
    now = datetime.now(timezone.utc)
    valid_from = valid_from or now - timedelta(minutes=5)
    with connect() as conn:
        basis_id = conn.execute(
            """
            INSERT INTO authorization_bases(domain_id, valid_from, valid_until, revoked_at)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (domain_id, valid_from, valid_until, revoked_at),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO scan_targets(domain_id, authorization_basis_id, status) VALUES (%s, %s, %s)",
            (domain_id, basis_id, status),
        )


def test_scan_reservation_requires_an_authorization_record(authorization_db):
    with pytest.raises(main.ScanAuthorizationError):
        main.reserve_scan_capacity(1)


@pytest.mark.parametrize(
    "authorization",
    [
        {"valid_from": datetime.now(timezone.utc) + timedelta(hours=1)},
        {"valid_until": datetime.now(timezone.utc) - timedelta(seconds=1)},
        {"revoked_at": datetime.now(timezone.utc) - timedelta(seconds=1)},
        {"status": "disabled"},
    ],
    ids=["not-yet-valid", "expired", "revoked", "disabled-target"],
)
def test_scan_reservation_rejects_invalid_authorization(authorization_db, authorization):
    _add_target(authorization_db, **authorization)
    with pytest.raises(main.ScanAuthorizationError):
        main.reserve_scan_capacity(1)


def test_scan_reservation_requires_authorization_for_the_exact_domain(authorization_db):
    _add_target(authorization_db, domain_id=2)
    with pytest.raises(main.ScanAuthorizationError):
        main.reserve_scan_capacity(1)


def test_scan_reservation_accepts_current_active_authorization(authorization_db):
    _add_target(authorization_db)
    reservation = main.reserve_scan_capacity(1)
    assert reservation is not None
    main.release_scan_capacity(*reservation)
