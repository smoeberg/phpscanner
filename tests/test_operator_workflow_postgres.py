"""End-to-end PostgreSQL test for the single-operator scan workflow."""
import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import uuid

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy.engine import make_url

from app import main, worker


@pytest.fixture
def operator_workflow_db(monkeypatch):
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("DATABASE_URL is required for PostgreSQL integration tests")

    schema = "operator_workflow_" + uuid.uuid4().hex
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
    config.set_main_option("sqlalchemy.url", isolated_url.replace("%", "%%"))
    command.upgrade(config, "head")

    def connect():
        return psycopg.connect(database_url, options=f"-c search_path={schema}")

    monkeypatch.setattr(main, "db_connect", connect)
    try:
        yield connect
    finally:
        with psycopg.connect(database_url, autocommit=True) as admin:
            admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def test_operator_can_import_authorize_scan_review_and_export(
    operator_workflow_db, monkeypatch
):
    monkeypatch.setattr(main, "API_KEY", "workflow-test-secret")
    client = TestClient(main.app)
    headers = {"X-API-Key": "workflow-test-secret"}

    imported = client.post(
        "/domains/import",
        headers=headers,
        json={"domains": ["EXAMPLE.COM."], "source": "operator-workflow-test"},
    )
    assert imported.status_code == 200
    assert imported.json()["accepted_or_existing"] == 1

    domains = client.get("/domains", headers=headers)
    assert domains.status_code == 200
    assert len(domains.json()) == 1
    domain = domains.json()[0]
    assert domain["domain"] == "example.com"
    domain_id = domain["id"]

    prospect_response = client.post(
        "/prospects",
        headers=headers,
        json={"name": "Example Organization"},
    )
    assert prospect_response.status_code == 201
    prospect_id = prospect_response.json()["id"]
    association_response = client.post(
        f"/prospects/{prospect_id}/domains",
        headers=headers,
        json={"domain_id": domain_id},
    )
    assert association_response.status_code == 200
    assert association_response.json()["association_status"] == "unverified"

    challenge = client.post(
        f"/domains/{domain_id}/verification-challenge",
        headers=headers,
    )
    assert challenge.status_code == 200
    challenge_value = challenge.json()["record_value"]

    class TxtAnswer:
        strings = [challenge_value.encode("utf-8")]

    async def resolve_txt(name, record_type, lifetime):
        assert name == "_dk-php-scanner-verification.example.com."
        assert record_type == "TXT"
        assert lifetime == 5
        return [TxtAnswer()]

    monkeypatch.setattr(main.dns.asyncresolver, "resolve", resolve_txt)
    verified = client.post(f"/domains/{domain_id}/verify", headers=headers)
    assert verified.status_code == 200
    assert verified.json()["verified"] is True

    # DNS control proves control of the name, not permission to scan it.
    denied = client.post(f"/domains/{domain_id}/scan", headers=headers)
    assert denied.status_code == 403

    now = datetime.now(timezone.utc)
    authorization = client.post(
        f"/domains/{domain_id}/authorizations",
        headers=headers,
        json={
            "basis_type": "written_permission",
            "description": "Explicit permission for a bounded HTTP(S) observation",
            "evidence_reference": "test-evidence-SEC-22",
            "granted_by": "Authorized security contact",
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=7)).isoformat(),
        },
    )
    assert authorization.status_code == 200
    authorization_data = authorization.json()

    listed_authorizations = client.get(
        f"/domains/{domain_id}/authorizations",
        headers=headers,
    )
    assert listed_authorizations.status_code == 200
    assert listed_authorizations.json()[0]["currently_authorized"] is True

    submitted = client.post(f"/domains/{domain_id}/scan", headers=headers)
    assert submitted.status_code == 202
    job_id = submitted.json()["job_id"]
    assert submitted.json()["status"] == "queued"

    queued = client.get(f"/scan-jobs/{job_id}", headers=headers)
    assert queued.status_code == 200
    assert queued.json()["status"] == "queued"

    claimed = worker.claim_next_job()
    assert claimed is not None
    assert claimed[0] == job_id

    async def fake_probe(domain_name):
        assert domain_name == "example.com"
        return {
            "status_code": 200,
            "final_url": "https://example.com/",
            "server_header": "nginx",
            "powered_by": "PHP/8.3.1",
            "php_indicator": True,
            "version_observed": "8.3.1",
            "confidence": "version-disclosed",
            "notes": "Bounded observation; redirects are not followed.",
        }

    monkeypatch.setattr(main, "probe", fake_probe)
    asyncio.run(worker.process_job(claimed))

    completed = client.get(f"/scan-jobs/{job_id}", headers=headers)
    assert completed.status_code == 200
    completed_data = completed.json()
    assert completed_data["status"] == "succeeded"
    assert completed_data["attempts"] == 1
    scan_id = completed_data["scan_id"]
    assert scan_id is not None

    observations = client.get(
        f"/scans/{scan_id}/observations",
        headers=headers,
    )
    assert observations.status_code == 200
    observed = {item["observation_type"]: item["value"] for item in observations.json()}
    assert observed == {
        "http_status": "200",
        "server_header": "nginx",
        "x_powered_by": "PHP/8.3.1",
    }

    findings = client.get(f"/scans/{scan_id}/findings", headers=headers)
    assert findings.status_code == 200
    assert len(findings.json()) == 1
    finding = findings.json()[0]
    assert finding["finding_type"] == "php_runtime_disclosure"
    assert finding["assessment"] == "disclosed"
    assert finding["confidence"] == "high"
    assert finding["version_observed"] == "8.3.1"
    assert finding["evidence"]

    results = client.get("/results", headers=headers)
    assert results.status_code == 200
    assert results.json()[0]["scan_id"] == scan_id

    export = client.get("/results.csv", headers=headers)
    assert export.status_code == 200
    assert "text/csv" in export.headers["content-type"]
    csv_lines = export.text.splitlines()
    assert csv_lines[0].startswith("domain,scanned_at,status_code")
    assert "example.com" in csv_lines[1]
    assert "PHP/8.3.1" in csv_lines[1]
    assert "php_runtime_disclosure" in csv_lines[1]
    assert "disclosed" in csv_lines[1]
    assert "prospect_associations" in csv_lines[0]
    assert "Example Organization" in csv_lines[1]
    assert "unverified" in csv_lines[1]
    assert String(prospect_id) in csv_lines[1]

    assert authorization_data["scan_target_id"]


def test_operator_can_create_list_prospects_and_associate_domains(
    operator_workflow_db, monkeypatch
):
    monkeypatch.setattr(main, "API_KEY", "prospect-test-secret")
    client = TestClient(main.app)
    headers = {"X-API-Key": "prospect-test-secret"}

    assert client.get("/prospects").status_code == 401
    assert client.post("/prospects", json={"name": "Unauthorized"}).status_code == 401

    created = client.post(
        "/prospects",
        headers=headers,
        json={
            "name": "  Example Organization  ",
            "organization_number": " 12345678 ",
            "website_url": "https://example.com",
            "notes": "Internal research prospect",
        },
    )
    assert created.status_code == 201
    prospect = created.json()
    assert prospect["name"] == "Example Organization"
    assert prospect["organization_number"] == "12345678"
    assert prospect["domains"] == []

    imported = client.post(
        "/domains/import",
        headers=headers,
        json={"domains": ["example.com"], "source": "prospect-test"},
    )
    assert imported.status_code == 200
    domain_id = client.get("/domains", headers=headers).json()[0]["id"]

    missing_prospect = client.post(
        "/prospects/999999/domains",
        headers=headers,
        json={"domain_id": domain_id},
    )
    assert missing_prospect.status_code == 404
    missing_domain = client.post(
        f"/prospects/{prospect['id']}/domains",
        headers=headers,
        json={"domain_id": 999999},
    )
    assert missing_domain.status_code == 404

    associated = client.post(
        f"/prospects/{prospect['id']}/domains",
        headers=headers,
        json={"domain_id": domain_id},
    )
    assert associated.status_code == 200
    association = associated.json()
    assert association["domain"] == "example.com"
    assert association["association_status"] == "unverified"

    repeated = client.post(
        f"/prospects/{prospect['id']}/domains",
        headers=headers,
        json={"domain_id": domain_id},
    )
    assert repeated.status_code == 200
    assert repeated.json()["association_id"] == association["association_id"]

    second_import = client.post(
        "/domains/import",
        headers=headers,
        json={"domains": ["second.example"], "source": "prospect-test"},
    )
    assert second_import.status_code == 200
    second_domain_id = next(
        item["id"] for item in client.get("/domains", headers=headers).json()
        if item["domain"] == "second.example"
    )
    second_association = client.post(
        f"/prospects/{prospect['id']}/domains",
        headers=headers,
        json={"domain_id": second_domain_id},
    )
    assert second_association.status_code == 200
    assert second_association.json()["association_status"] == "unverified"

    # Prospect association and DNS control do not grant scan authorization.
    with operator_workflow_db() as conn:
        conn.execute(
            "UPDATE domains SET verified_at = now() WHERE id = %s",
            (domain_id,),
        )
    denied = client.post(f"/domains/{domain_id}/scan", headers=headers)
    assert denied.status_code == 403

    listed = client.get("/prospects", headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    listed_prospect = listed.json()[0]
    assert listed_prospect["id"] == prospect["id"]
    assert [item["domain"] for item in listed_prospect["domains"]] == [
        "example.com", "second.example"
    ]
    assert all(
        item["association_status"] == "unverified"
        for item in listed_prospect["domains"]
    )
    assert client.get("/prospects?limit=1", headers=headers).json()[0]["domains"] == listed_prospect["domains"]

    filtered = client.get("/prospects?q=12345678", headers=headers)
    assert filtered.status_code == 200
    assert len(filtered.json()) == 1
