"""PostgreSQL integration tests for fail-closed scan authorization."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
import threading
import time
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient

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
                    domain TEXT NOT NULL UNIQUE,
                    verified_at TIMESTAMPTZ NOT NULL DEFAULT now()
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


def test_operator_can_create_list_disable_and_revoke_authorization(authorization_db, monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "test-secret")
    client = TestClient(main.app)
    headers = {"X-API-Key": "test-secret"}
    payload = {
        "basis_type": "written_permission",
        "description": "Written approval for a limited, non-invasive review",
        "evidence_reference": "internal-ticket-SEC-1042",
        "granted_by": "Security contact",
        "valid_from": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }

    created = client.post("/domains/1/authorizations", json=payload, headers=headers)
    assert created.status_code == 200
    record = created.json()
    assert record["domain"] == "authorized.example"
    assert record["basis_type"] == "written_permission"
    assert record["target_status"] == "active"

    listed = client.get("/domains/1/authorizations", headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["currently_authorized"] is True

    disabled = client.patch(
        f"/scan-targets/{record['scan_target_id']}",
        json={"status": "disabled"},
        headers=headers,
    )
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "disabled"
    with pytest.raises(main.ScanAuthorizationError):
        main.reserve_scan_capacity(1)

    reenabled = client.patch(
        f"/scan-targets/{record['scan_target_id']}",
        json={"status": "active"},
        headers=headers,
    )
    assert reenabled.status_code == 200
    assert main.reserve_scan_capacity(1) is not None


def _assert_backend_waits_on_lock(connect, backend_pid):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with connect() as conn:
            blockers = conn.execute(
                "SELECT pg_blocking_pids(%s)",
                (backend_pid,),
            ).fetchone()[0]
        if blockers:
            return
        time.sleep(0.01)
    raise AssertionError(f"PostgreSQL backend {backend_pid} did not wait on a lock")


def test_revoking_authorization_prevents_future_scan_reservations(authorization_db, monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "test-secret")
    client = TestClient(main.app)
    headers = {"X-API-Key": "test-secret"}
    _add_target(authorization_db)

    with authorization_db() as conn:
        authorization_id = conn.execute(
            "SELECT id FROM authorization_bases WHERE domain_id = 1"
        ).fetchone()[0]

    response = client.post(f"/authorizations/{authorization_id}/revoke", headers=headers)
    assert response.status_code == 200
    assert response.json()["authorization_id"] == authorization_id
    with pytest.raises(main.ScanAuthorizationError):
        main.reserve_scan_capacity(1)


def test_create_authorization_rejects_invalid_date_range(authorization_db, monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "test-secret")
    client = TestClient(main.app)
    now = datetime.now(timezone.utc)
    response = client.post(
        "/domains/1/authorizations",
        headers={"X-API-Key": "test-secret"},
        json={
            "basis_type": "written_permission",
            "evidence_reference": "approval-123",
            "granted_by": "Authorized contact",
            "valid_from": now.isoformat(),
            "valid_until": (now - timedelta(seconds=1)).isoformat(),
        },
    )
    assert response.status_code == 400



def test_revocation_waits_for_in_flight_authorized_reservation(authorization_db, monkeypatch):
    """A reservation that locks authorization first commits before revocation."""
    _add_target(authorization_db)
    with authorization_db() as conn:
        authorization_id = conn.execute(
            "SELECT id FROM authorization_bases WHERE domain_id = 1"
        ).fetchone()[0]

    monkeypatch.setattr(main, "API_KEY", "test-secret")
    client = TestClient(main.app)
    headers = {"X-API-Key": "test-secret"}
    authorization_locked = threading.Event()
    allow_reservation_to_finish = threading.Event()
    revocation_started = threading.Event()
    revocation_backend_pid = []

    class ObservedConnection:
        def __init__(self, connection):
            self.connection = connection
            self.backend_pid = connection.execute("SELECT pg_backend_pid()").fetchone()[0]

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def execute(self, query, *args, **kwargs):
            normalized = " ".join(query.split()).upper()
            if "FOR SHARE OF ST, AB" in normalized:
                result = self.connection.execute(query, *args, **kwargs)
                authorization_locked.set()
                if not allow_reservation_to_finish.wait(timeout=10):
                    raise TimeoutError("test did not release reservation lock")
                return result
            if "UPDATE AUTHORIZATION_BASES" in normalized:
                revocation_backend_pid.append(self.backend_pid)
                revocation_started.set()
            return self.connection.execute(query, *args, **kwargs)

    monkeypatch.setattr(
        main, "db_connect",
        lambda: ObservedConnection(authorization_db()),
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        reservation_future = pool.submit(main.reserve_scan_capacity, 1)
        assert authorization_locked.wait(timeout=10)
        revocation_future = pool.submit(
            client.post,
            f"/authorizations/{authorization_id}/revoke",
            headers=headers,
        )
        try:
            assert revocation_started.wait(timeout=10)
            # Confirm PostgreSQL itself reports the UPDATE backend blocked by
            # the reservation transaction, rather than relying on timing.
            _assert_backend_waits_on_lock(authorization_db, revocation_backend_pid[0])
            assert not revocation_future.done()
        finally:
            allow_reservation_to_finish.set()

        reservation = reservation_future.result(timeout=10)
        response = revocation_future.result(timeout=10)

    assert reservation is not None
    assert response.status_code == 200
    main.release_scan_capacity(*reservation)
    with pytest.raises(main.ScanAuthorizationError):
        main.reserve_scan_capacity(1)


def test_reservation_waits_for_revocation_commit_then_denies_scan(authorization_db, monkeypatch):
    """A revocation that locks authorization first commits before reservation."""
    _add_target(authorization_db)
    with authorization_db() as conn:
        authorization_id = conn.execute(
            "SELECT id FROM authorization_bases WHERE domain_id = 1"
        ).fetchone()[0]

    monkeypatch.setattr(main, "API_KEY", "test-secret")
    client = TestClient(main.app)
    headers = {"X-API-Key": "test-secret"}
    revocation_updated = threading.Event()
    allow_revocation_to_commit = threading.Event()
    reservation_query_started = threading.Event()
    revocation_backend_pid = []
    reservation_backend_pid = []

    class ObservedConnection:
        def __init__(self, connection):
            self.connection = connection
            self.backend_pid = connection.execute("SELECT pg_backend_pid()").fetchone()[0]

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def execute(self, query, *args, **kwargs):
            normalized = " ".join(query.split()).upper()
            if "UPDATE AUTHORIZATION_BASES" in normalized:
                revocation_backend_pid.append(self.backend_pid)
                result = self.connection.execute(query, *args, **kwargs)
                revocation_updated.set()
                if not allow_revocation_to_commit.wait(timeout=10):
                    raise TimeoutError("test did not release revocation lock")
                return result
            if "FOR SHARE OF ST, AB" in normalized:
                reservation_backend_pid.append(self.backend_pid)
                reservation_query_started.set()
            return self.connection.execute(query, *args, **kwargs)

    monkeypatch.setattr(
        main, "db_connect",
        lambda: ObservedConnection(authorization_db()),
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        revocation_future = pool.submit(
            client.post,
            f"/authorizations/{authorization_id}/revoke",
            headers=headers,
        )
        assert revocation_updated.wait(timeout=10)
        reservation_future = pool.submit(main.reserve_scan_capacity, 1)
        try:
            assert reservation_query_started.wait(timeout=10)
            # Confirm the reservation query is blocked by the uncommitted
            # revocation update, rather than relying on thread scheduling.
            _assert_backend_waits_on_lock(authorization_db, reservation_backend_pid[0])
            assert not reservation_future.done()
        finally:
            allow_revocation_to_commit.set()

        response = revocation_future.result(timeout=10)
        with pytest.raises(main.ScanAuthorizationError):
            reservation_future.result(timeout=10)

    assert response.status_code == 200


def test_scan_reservation_requires_verified_domain(authorization_db):
    _add_target(authorization_db)
    with authorization_db() as conn:
        conn.execute("UPDATE domains SET verified_at = NULL WHERE id = 1")
    with pytest.raises(main.ScanAuthorizationError, match="verification"):
        main.reserve_scan_capacity(1)


def test_verification_reset_serializes_before_scan_reservation(authorization_db, monkeypatch):
    """A challenge reset that locks the domain first must deny the reservation."""
    _add_target(authorization_db)
    reset_updated = threading.Event()
    allow_reset_commit = threading.Event()
    reservation_query_started = threading.Event()
    reservation_pid = []

    def reset_verification():
        with authorization_db() as conn:
            conn.execute("UPDATE domains SET verified_at = NULL WHERE id = 1")
            reset_updated.set()
            if not allow_reset_commit.wait(timeout=10):
                raise TimeoutError("test did not release verification reset")

    class ObservedConnection:
        def __init__(self, connection):
            self.connection = connection
            self.backend_pid = connection.execute("SELECT pg_backend_pid()").fetchone()[0]
        def __enter__(self):
            self.connection.__enter__()
            return self
        def __exit__(self, *args):
            return self.connection.__exit__(*args)
        def execute(self, query, *args, **kwargs):
            if "select verified_at from domains" in " ".join(query.split()).lower():
                reservation_pid.append(self.backend_pid)
                reservation_query_started.set()
            return self.connection.execute(query, *args, **kwargs)

    monkeypatch.setattr(main, "db_connect", lambda: ObservedConnection(authorization_db()))
    with ThreadPoolExecutor(max_workers=2) as pool:
        reset_future = pool.submit(reset_verification)
        assert reset_updated.wait(timeout=10)
        reservation_future = pool.submit(main.reserve_scan_capacity, 1)
        try:
            assert reservation_query_started.wait(timeout=10)
            _assert_backend_waits_on_lock(authorization_db, reservation_pid[0])
            assert not reservation_future.done()
        finally:
            allow_reset_commit.set()
        reset_future.result(timeout=10)
        with pytest.raises(main.ScanAuthorizationError, match="verification"):
            reservation_future.result(timeout=10)


def test_scan_reservation_serializes_before_verification_reset(authorization_db, monkeypatch):
    """A reservation holding the domain row commits before challenge invalidation."""
    _add_target(authorization_db)
    domain_locked = threading.Event()
    allow_reservation_commit = threading.Event()
    challenge_started = threading.Event()
    challenge_pid = []

    class ObservedConnection:
        def __init__(self, connection):
            self.connection = connection
            self.backend_pid = connection.execute("SELECT pg_backend_pid()").fetchone()[0]
        def __enter__(self):
            self.connection.__enter__()
            return self
        def __exit__(self, *args):
            return self.connection.__exit__(*args)
        def execute(self, query, *args, **kwargs):
            result = self.connection.execute(query, *args, **kwargs)
            if "select verified_at from domains" in " ".join(query.split()).lower():
                domain_locked.set()
                if not allow_reservation_commit.wait(timeout=10):
                    raise TimeoutError("test did not release reservation lock")
            return result

    monkeypatch.setattr(main, "db_connect", lambda: ObservedConnection(authorization_db()))
    def reset_verification():
        with authorization_db() as conn:
            challenge_pid.append(conn.execute("SELECT pg_backend_pid()").fetchone()[0])
            challenge_started.set()
            conn.execute("UPDATE domains SET verified_at = NULL WHERE id = 1")

    with ThreadPoolExecutor(max_workers=2) as pool:
        reservation_future = pool.submit(main.reserve_scan_capacity, 1)
        assert domain_locked.wait(timeout=10)
        challenge_future = pool.submit(reset_verification)
        try:
            assert challenge_started.wait(timeout=10)
            _assert_backend_waits_on_lock(authorization_db, challenge_pid[0])
            assert not challenge_future.done()
        finally:
            allow_reservation_commit.set()
        reservation = reservation_future.result(timeout=10)
        challenge_future.result(timeout=10)

    assert reservation is not None
    main.release_scan_capacity(*reservation)
    with authorization_db() as conn:
        assert conn.execute("SELECT verified_at FROM domains WHERE id = 1").fetchone()[0] is None
