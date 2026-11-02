import re
from collections import Counter

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


def test_operator_domain_input_and_domain_list_have_distinct_ids():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    ids = re.findall(r'\bid="([^"]+)"', response.text)
    duplicates = [element_id for element_id, count in Counter(ids).items() if count > 1]
    assert duplicates == []
    assert 'id="domain-import-input"' in response.text
    assert 'id="domain-list"' in response.text
    assert '$("domain-import-input").value' in response.text
    assert '$("domain-list").replaceChildren' in response.text


def test_operator_home_exposes_authenticated_csv_download():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert 'id="export-csv"' in response.text
    assert 'fetch("/results.csv"' in response.text
    assert '"X-API-Key": apiKey' in response.text
    assert 'link.download = "dk-php-scanner-results.csv"' in response.text
    assert "localStorage" not in response.text
    assert "sessionStorage" not in response.text


def test_operator_home_displays_recent_scan_results_from_authenticated_api():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert 'id="scan-results"' in response.text
    assert 'api("/results?limit=" + (scanPageSize + 1) + "&offset=" + scanOffset)' in response.text
    assert '"PHP-indikation"' in response.text
    assert "En PHP-indikation er ikke i sig selv dokumentation for en sårbarhed." in response.text


def test_operator_home_exposes_scan_finding_and_observation_details():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert 'id="scan-detail"' in response.text
    assert 'api("/scans/" + scanId + "/findings")' in response.text
    assert 'api("/scans/" + scanId + "/observations")' in response.text
    assert 'details.addEventListener("click", () => loadScanDetails(scan.scan_id))' in response.text


def test_operator_home_requires_current_authorization_before_enabling_scan_button():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert 'api("/domains/" + d.id + "/authorizations")' in response.text
    assert "authorizations.some(a => a.currently_authorized)" in response.text
    assert "scan.disabled = !d.verified || !currentlyAuthorized" in response.text
    assert "Gyldig tilladelse" in response.text
    assert "Ingen gyldig tilladelse" in response.text


def test_operator_authorization_list_explains_validity_and_inactive_reasons():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert 'new Date(a.valid_from).getTime()' in response.text
    assert 'new Date(a.valid_until).getTime()' in response.text
    assert 'if (a.revoked_at) status = "Tilbagekaldt"' in response.text
    assert 'status = "Afventer start"' in response.text
    assert 'status = "Udløbet"' in response.text
    assert 'status = "Scanmål deaktiveret"' in response.text
    assert '"Gyldig fra","Gyldig til","Status"' in response.text


def test_operator_scan_history_has_offset_pagination_controls():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert 'id="scan-prev"' in response.text
    assert 'id="scan-next"' in response.text
    assert 'id="scan-page"' in response.text
    assert 'let scanOffset = 0;' in response.text
    assert 'api("/results?limit=" + (scanPageSize + 1) + "&offset=" + scanOffset)' in response.text
    assert 'const hasMoreScans = scans.length > scanPageSize;' in response.text
    assert '$("scan-next").disabled = !hasMoreScans;' in response.text
    assert 'scanOffset=Math.max(0,scanOffset-scanPageSize)' in response.text
    assert 'scanOffset+=scanPageSize' in response.text



def test_operator_lists_support_authenticated_search_filter():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert 'id="list-search"' in response.text
    assert 'id="search-lists"' in response.text
    assert 'api("/prospects" + listSearch())' in response.text
    assert 'api("/domains" + listSearch())' in response.text
    assert 'encodeURIComponent(query)' in response.text
    assert '$("list-search").addEventListener("keydown"' in response.text


def test_operator_prospect_and_domain_lists_have_independent_offset_pagination():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert 'id="prospect-prev"' in response.text
    assert 'id="prospect-next"' in response.text
    assert 'id="prospect-page"' in response.text
    assert 'id="domain-prev"' in response.text
    assert 'id="domain-next"' in response.text
    assert 'id="domain-page"' in response.text
    assert 'let prospectOffset = 0;' in response.text
    assert 'let domainOffset = 0;' in response.text
    assert 'const listPageSize = 50;' in response.text
    assert 'api("/prospects" + listQuery(prospectOffset))' in response.text
    assert 'api("/domains" + listQuery(domainOffset))' in response.text
    assert 'const hasMoreProspects = prospectResults.length > listPageSize;' in response.text
    assert 'const hasMoreDomains = domainResults.length > listPageSize;' in response.text
    assert 'prospectOffset+=listPageSize' in response.text
    assert 'domainOffset+=listPageSize' in response.text
    assert 'prospectOffset = 0;' in response.text
    assert 'domainOffset = 0;' in response.text
