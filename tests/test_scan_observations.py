from datetime import datetime, timezone

from app import main, worker


class _Result:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


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
        if normalized.startswith("UPDATE scan_jobs"):
            return _Result((9,))
        return _Result()


def test_persist_result_stores_raw_http_observations(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(main, "db_connect", lambda: connection)

    worker.persist_result(
        job_id=9,
        domain_id=3,
        token="job-fence",
        result={
            "status_code": 200,
            "final_url": "https://authorized.example/",
            "server_header": "nginx",
            "powered_by": "PHP/8.2.12",
            "php_indicator": True,
            "version_observed": "8.2.12",
            "confidence": "version-disclosed",
            "notes": "Header observation only.",
        },
    )

    observations = [
        params for statement, params in connection.statements
        if "INSERT INTO scan_observations" in statement
    ]
    assert observations == [
        (41, "http_status", "200", "http.response.status"),
        (41, "server_header", "nginx", "http.response.header.server"),
        (41, "x_powered_by", "PHP/8.2.12", "http.response.header.x-powered-by"),
    ]


def test_persist_result_skips_absent_http_headers(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(main, "db_connect", lambda: connection)

    worker.persist_result(
        job_id=10,
        domain_id=3,
        token="job-fence-2",
        result={
            "status_code": None,
            "final_url": None,
            "server_header": "",
            "powered_by": "",
            "php_indicator": False,
            "version_observed": None,
            "confidence": "unreachable",
            "notes": "No HTTP response.",
        },
    )

    observations = [
        statement for statement, _params in connection.statements
        if "INSERT INTO scan_observations" in statement
    ]
    assert observations == []
