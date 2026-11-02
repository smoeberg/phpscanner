import json
import logging

from app.observability import JsonLogFormatter


def test_json_log_formatter_emits_structured_request_fields():
    record = logging.LogRecord(
        name="scanner.api",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="http_request_completed",
        args=(),
        exc_info=None,
    )
    record.event = "http_request"
    record.request_id = "request-123"
    record.method = "GET"
    record.path = "/health/ready"
    record.status_code = 200
    record.duration_ms = 1.25

    payload = json.loads(JsonLogFormatter().format(record))

    assert payload["level"] == "info"
    assert payload["logger"] == "scanner.api"
    assert payload["event"] == "http_request"
    assert payload["request_id"] == "request-123"
    assert payload["method"] == "GET"
    assert payload["path"] == "/health/ready"
    assert payload["status_code"] == 200
    assert payload["duration_ms"] == 1.25


def test_json_log_formatter_does_not_add_unapproved_record_fields():
    record = logging.LogRecord(
        name="scanner.api",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="completed",
        args=(),
        exc_info=None,
    )
    record.authorization_header = "must-not-be-serialized"

    payload = json.loads(JsonLogFormatter().format(record))

    assert "authorization_header" not in payload
    assert "must-not-be-serialized" not in json.dumps(payload)
