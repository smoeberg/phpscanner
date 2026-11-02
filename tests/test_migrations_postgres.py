"""PostgreSQL integration tests for the non-destructive Alembic baseline."""
from pathlib import Path
import os
import uuid

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url


@pytest.fixture
def migration_database(monkeypatch):
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("DATABASE_URL is required for migration integration tests")

    schema = "migration_test_" + uuid.uuid4().hex
    with psycopg.connect(database_url, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{schema}"')

    url = make_url(database_url)
    query = dict(url.query)
    query["options"] = f"-csearch_path={schema}"
    isolated_url = url.set(
        drivername="postgresql+psycopg",
        query=query,
    ).render_as_string(hide_password=False)
    monkeypatch.setenv("DATABASE_URL", isolated_url)

    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))

    def connect():
        return psycopg.connect(database_url, options=f"-c search_path={schema}")

    try:
        yield schema, config, connect
    finally:
        with psycopg.connect(database_url, autocommit=True) as admin:
            admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def test_migration_creates_fresh_schema(migration_database):
    _schema, config, connect = migration_database

    command.upgrade(config, "head")

    with connect() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"
            )
        }
        assert {
            "domains",
            "scans",
            "scan_rate_limits",
            "scan_slots",
            "prospects",
            "prospect_domains",
            "authorization_bases",
            "scan_targets",
            "scan_jobs",
            "scan_observations",
            "scan_findings",
            "alembic_version",
        } <= tables
        assert conn.execute("SELECT count(*) FROM scan_slots").fetchone()[0] == 4


def test_migration_preserves_existing_domains_and_scans(migration_database):
    _schema, config, connect = migration_database

    with connect() as conn:
        conn.execute("""
            CREATE TABLE domains (
                id BIGSERIAL PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL DEFAULT 'manual',
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        conn.execute("""
            CREATE TABLE scans (
                id BIGSERIAL PRIMARY KEY,
                domain_id BIGINT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                scanned_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        domain_id = conn.execute(
            "INSERT INTO domains(domain) VALUES ('preserved.example') RETURNING id"
        ).fetchone()[0]
        scan_id = conn.execute(
            "INSERT INTO scans(domain_id) VALUES (%s) RETURNING id",
            (domain_id,),
        ).fetchone()[0]

    command.upgrade(config, "head")

    with connect() as conn:
        assert conn.execute(
            "SELECT id, domain FROM domains"
        ).fetchall() == [(domain_id, "preserved.example")]
        assert conn.execute(
            "SELECT id, domain_id FROM scans"
        ).fetchall() == [(scan_id, domain_id)]
        assert conn.execute("SELECT count(*) FROM scan_slots").fetchone()[0] == 4
