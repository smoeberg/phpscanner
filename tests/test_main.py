import pytest
from fastapi import HTTPException

from app.main import DomainImport, normalize_domain, require_api_key


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        (" EXAMPLE.COM. ", "example.com"),
        ("https://example.com/", "example.com"),
        ("https://sub.example.com", "sub.example.com"),
        ("æøå.dk", "xn--5cab8c.dk"),
    ],
)
def test_normalize_domain_accepts_valid_domains(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "localhost",
        "example.com/path",
        "https://example.com/path",
        "https://user:pass@example.com",
        "example.com:8080",
        "127.0.0.1",
        "-bad.example",
        "bad..example",
    ],
)
def test_normalize_domain_rejects_invalid_or_unsupported_inputs(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


def test_domain_import_requires_at_least_one_domain():
    with pytest.raises(ValueError):
        DomainImport(domains=[])


def test_domain_import_rejects_more_than_1000_domains():
    with pytest.raises(ValueError):
        DomainImport(domains=[f"host{i}.example" for i in range(1001)])


def test_api_key_accepts_configured_key():
    assert require_api_key("test-secret") is None


@pytest.mark.parametrize("provided", [None, "", "wrong-secret"])
def test_api_key_rejects_missing_or_wrong_key(provided):
    with pytest.raises(HTTPException) as exc:
        require_api_key(provided)
    assert exc.value.status_code == 401
