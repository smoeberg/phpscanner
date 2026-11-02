from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app import main, worker


class _Result:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows or []

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class _Connection:
    def __init__(self):
        self.statements = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, params=None):
        self.statements.append((statement, params))
        normalized = " ".join(statement.split())
        if normalized.startswith("INSERT INTO scans"):
            return _Result((41,))
        if normalized.startswith("SELECT id, observation_type, observed_value, source"):
            rows = []
            next_id = 1
            for query, values in self.statements:
                if "INSERT INTO scan_observations" in query:
                    rows.append((next_id, values[1], values[2], values[3]))
                    next_id += 1
            return _Result(rows=rows)
        if normalized.startswith("UPDATE scan_jobs"):
            return _Result((9,))
        return _Result()


def _scan_result(status=200, server="nginx", powered="PHP/8.2.12"):
    return {
        "status_code": status,
        "final_url": "https://authorized.example/",
        "server_header": server,
        "powered_by": powered,
        "php_indicator": bool(powered or "php" in server.lower()),
        "version_observed": "8.2.12" if powered == "PHP/8.2.12" else None,
        "confidence": "version-disclosed",
        "notes": "Header observation only.",
    }


def test_persist_result_stores_raw_observations_and_derived_finding(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(main, "db_connect", lambda: connection)

    worker.persist_result(job_id=9, domain_id=3, token="job-fence", result=_scan_result())

    observations = [
        params for statement, params in connection.statements
        if "INSERT INTO scan_observations" in statement
    ]
    assert observations == [
        (41, "http_status", "200", "http.response.status"),
        (41, "server_header", "nginx", "http.response.header.server"),
        (41, "x_powered_by", "PHP/8.2.12", "http.response.header.x-powered-by"),
    ]
    finding = next(
        params for statement, params in connection.statements
        if "INSERT INTO scan_findings" in statement
    )
    assert finding[:5] == (41, "php_runtime_disclosure", "disclosed", "high", "8.2.12")
    assert "does not establish an outdated or vulnerable runtime" in finding[5]
    assert '"observation_id": 3' in finding[6]


def test_persist_result_creates_undetermined_finding_when_headers_are_absent(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(main, "db_connect", lambda: connection)

    result = _scan_result(status=None, server="", powered="")
    result.update({"php_indicator": False, "version_observed": None, "confidence": "unreachable"})
    worker.persist_result(job_id=10, domain_id=3, token="job-fence-2", result=result)

    assert not any("INSERT INTO scan_observations" in sql for sql, _ in connection.statements)
    finding = next(params for sql, params in connection.statements if "INSERT INTO scan_findings" in sql)
    assert finding[2:5] == ("undetermined", "undetermined", None)
    assert finding[6] == "[]"


def test_server_header_php_indicator_is_low_confidence():
    from app.findings import derive_findings

    finding = derive_findings([{
        "id": 1,
        "observation_type": "server_header",
        "observed_value": "PHP/8.1",
        "source": "http.response.header.server",
    }])[0]
    assert finding["assessment"] == "possible"
    assert finding["confidence"] == "low"
    assert finding["version_observed"] is None


def test_disclosed_php_version_is_not_marked_vulnerable():
    from app.findings import derive_findings

    finding = derive_findings([{
        "id": 1,
        "observation_type": "x_powered_by",
        "observed_value": "PHP/8.2.12",
        "source": "http.response.header.x-powered-by",
    }])[0]
    assert finding["assessment"] == "disclosed"
    assert finding["version_observed"] == "8.2.12"
    assert "vulnerable runtime" in finding["rationale"]
    assert "CVE" not in finding["rationale"]


def test_scan_findings_endpoint_is_api_key_protected_and_returns_evidence(monkeypatch):
    now = datetime.now(timezone.utc)

    class FakeConnection:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def execute(self, query, _params):
            self.query = query
            return self
        def fetchone(self): return (41,)
        def fetchall(self):
            return [(5, "php_runtime_disclosure", "disclosed", "high", "8.2.12",
                     "Header disclosure only.", [{"observation_id": 3}], now)]

    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    monkeypatch.setattr(main, "API_KEY", "test-secret")
    client = TestClient(main.app)

    assert client.get("/scans/41/findings").status_code == 401
    response = client.get("/scans/41/findings", headers={"X-API-Key": "test-secret"})
    assert response.status_code == 200
    assert response.json()[0]["assessment"] == "disclosed"
    assert response.json()[0]["evidence"] == [{"observation_id": 3}]
