from fastapi.testclient import TestClient

from app.main import app


def test_operator_home_serves_interface_without_exposing_api_key(monkeypatch):
    monkeypatch.setattr("app.main.API_KEY", "test-secret")

    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "PHP Exposure Scanner" in response.text
    assert 'id="key"' in response.text
    assert "test-secret" not in response.text
    assert "localStorage" not in response.text
    assert "sessionStorage" not in response.text


def test_operator_home_contains_only_existing_authorized_workflows():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "/domains/import" in response.text
    assert "/prospects" in response.text
    assert "/authorizations/" in response.text
    assert "/domains/" in response.text
    assert "DNS-verifikation" in response.text
    assert "d.verified" in response.text
    assert "Start scanning" in response.text
