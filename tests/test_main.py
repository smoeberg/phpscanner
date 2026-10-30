import asyncio
import socket

import httpx

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import main
from app.main import (
    DomainImport,
    _pinned_request_target,
    app,
    normalize_domain,
    require_api_key,
    resolve_public_ips,
)


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


def test_protected_domains_endpoint_rejects_missing_api_key():
    response = TestClient(app).get("/domains")
    assert response.status_code == 401


def test_protected_import_endpoint_rejects_wrong_api_key():
    response = TestClient(app).post(
        "/domains/import",
        headers={"X-API-Key": "wrong-secret"},
        json={"domains": ["example.com"]},
    )
    assert response.status_code == 401


def _addrinfo(ip):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, 0, 0, 0) if family == socket.AF_INET6 else (ip, 0)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


def test_resolve_public_ips_returns_unique_public_addresses(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            _addrinfo("8.8.8.8"),
            _addrinfo("1.1.1.1"),
            _addrinfo("8.8.8.8"),
        ],
    )

    assert resolve_public_ips("example.com") == ["1.1.1.1", "8.8.8.8"]


@pytest.mark.parametrize("private_ip", ["127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "fc00::1"])
def test_resolve_public_ips_rejects_non_public_addresses(monkeypatch, private_ip):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: [_addrinfo("8.8.8.8"), _addrinfo(private_ip)]
    )

    with pytest.raises(RuntimeError, match="ikke-offentlig IP"):
        resolve_public_ips("example.com")


def test_resolve_public_ips_rejects_empty_dns_answer(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])

    with pytest.raises(RuntimeError, match="Ingen DNS-adresser"):
        resolve_public_ips("example.com")


def test_resolve_public_ips_wraps_dns_errors(monkeypatch):
    def fail_lookup(*args, **kwargs):
        raise socket.gaierror("temporary DNS failure")

    monkeypatch.setattr(socket, "getaddrinfo", fail_lookup)

    with pytest.raises(RuntimeError, match="DNS-opslag fejlede"):
        resolve_public_ips("example.com")


def test_pinned_request_target_uses_ip_but_preserves_hostname_for_http_and_tls():
    url, headers, extensions = _pinned_request_target("example.com", "8.8.8.8", "https")

    assert url == "https://8.8.8.8/"
    assert headers == {"Host": "example.com"}
    assert extensions == {"sni_hostname": b"example.com"}


def test_pinned_request_target_formats_ipv6_address():
    url, headers, extensions = _pinned_request_target("example.com", "2606:4700:4700::1111", "http")

    assert url == "http://[2606:4700:4700::1111]/"
    assert headers["Host"] == "example.com"
    assert extensions["sni_hostname"] == b"example.com"



def test_probe_sends_request_to_pinned_ip_with_original_host_and_tls_name(monkeypatch):
    observed = {}

    async def handler(request):
        observed["url"] = request.url
        observed["host"] = request.headers.get("host")
        observed["sni_hostname"] = request.extensions.get("sni_hostname")
        return httpx.Response(
            200,
            headers={"server": "test-server", "x-powered-by": "PHP/8.2.1"},
            content=b"ok",
        )

    real_async_client = httpx.AsyncClient

    def client_with_mock_transport(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(main, "resolve_public_ips", lambda _domain: ["8.8.8.8"])
    monkeypatch.setattr(main.httpx, "AsyncClient", client_with_mock_transport)

    result = asyncio.run(main.probe("example.com"))

    assert observed["url"].host == "8.8.8.8"
    assert observed["host"] == "example.com"
    assert observed["sni_hostname"] == b"example.com"
    assert result["status_code"] == 200
    assert result["version_observed"] == "8.2.1"
