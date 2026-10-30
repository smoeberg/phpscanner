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
    _read_response_body_limited,
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


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        ([_addrinfo("8.8.8.8"), _addrinfo("1.1.1.1"), _addrinfo("8.8.8.8")], ["1.1.1.1", "8.8.8.8"]),
        ([], RuntimeError),
        ([_addrinfo("8.8.8.8"), _addrinfo("127.0.0.1")], RuntimeError),
    ],
)
def test_resolve_public_ips_async_validates_answers(monkeypatch, answers, expected):
    class FakeLoop:
        async def getaddrinfo(self, *args, **kwargs):
            return answers

    monkeypatch.setattr(main.asyncio, "get_running_loop", lambda: FakeLoop())

    if expected is RuntimeError:
        with pytest.raises(RuntimeError):
            asyncio.run(main.resolve_public_ips_async("example.com"))
    else:
        assert asyncio.run(main.resolve_public_ips_async("example.com")) == expected


def test_resolve_public_ips_async_wraps_dns_errors(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, *args, **kwargs):
            raise socket.gaierror("temporary DNS failure")

    monkeypatch.setattr(main.asyncio, "get_running_loop", lambda: FakeLoop())

    with pytest.raises(RuntimeError, match="DNS-opslag fejlede"):
        asyncio.run(main.resolve_public_ips_async("example.com"))


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

    async def fake_resolve_public_ips(_domain):
        return ["8.8.8.8"]

    monkeypatch.setattr(main, "resolve_public_ips_async", fake_resolve_public_ips)
    monkeypatch.setattr(main.httpx, "AsyncClient", client_with_mock_transport)

    result = asyncio.run(main.probe("example.com"))

    assert observed["url"].host == "8.8.8.8"
    assert observed["host"] == "example.com"
    assert observed["sni_hostname"] == b"example.com"
    assert result["status_code"] == 200
    assert result["version_observed"] == "8.2.1"



def test_probe_ignores_php_version_mentioned_only_in_response_body(monkeypatch):
    async def handler(_request):
        return httpx.Response(200, content=b"<html>Powered by PHP 5.6.40</html>")

    real_async_client = httpx.AsyncClient

    def client_with_mock_transport(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    async def fake_resolve_public_ips(_domain):
        return ["8.8.8.8"]

    monkeypatch.setattr(main, "resolve_public_ips_async", fake_resolve_public_ips)
    monkeypatch.setattr(main.httpx, "AsyncClient", client_with_mock_transport)
    result = asyncio.run(main.probe("example.com"))
    assert result["version_observed"] is None
    assert result["php_indicator"] is False
    assert result["confidence"] == "unknown"


def test_probe_uses_x_powered_by_for_php_version(monkeypatch):
    async def handler(_request):
        return httpx.Response(200, headers={"x-powered-by": "PHP/8.3.4"}, content=b"PHP 5.6.40")

    real_async_client = httpx.AsyncClient

    def client_with_mock_transport(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    async def fake_resolve_public_ips(_domain):
        return ["8.8.8.8"]

    monkeypatch.setattr(main, "resolve_public_ips_async", fake_resolve_public_ips)
    monkeypatch.setattr(main.httpx, "AsyncClient", client_with_mock_transport)
    result = asyncio.run(main.probe("example.com"))
    assert result["version_observed"] == "8.3.4"
    assert result["php_indicator"] is True


@pytest.mark.parametrize(
    ("status_code", "expected_confidence", "note"),
    [
        (403, "blocked", "HTTP 403"),
        (429, "rate-limited", "HTTP 429"),
    ],
)
def test_probe_classifies_blocked_and_rate_limited_responses(monkeypatch, status_code, expected_confidence, note):
    async def handler(_request):
        return httpx.Response(status_code, headers={"server": "nginx"})

    real_async_client = httpx.AsyncClient

    def client_with_mock_transport(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    async def fake_resolve_public_ips(_domain):
        return ["8.8.8.8"]

    monkeypatch.setattr(main, "resolve_public_ips_async", fake_resolve_public_ips)
    monkeypatch.setattr(main.httpx, "AsyncClient", client_with_mock_transport)
    result = asyncio.run(main.probe("example.com"))

    assert result["status_code"] == status_code
    assert result["confidence"] == expected_confidence
    assert note in result["notes"]
    assert result["php_indicator"] is False
    assert result["version_observed"] is None



@pytest.mark.parametrize(
    ("failure", "expected_note"),
    [
        (httpx.ReadTimeout("secret-hostname.internal"), "timeout"),
        (httpx.ConnectError("private-address=10.0.0.7"), "connection-failed"),
        (RuntimeError("resolver detail: private-address=10.0.0.7"), "dns-or-destination-rejected"),
        (ValueError("secret implementation detail"), "internal-error"),
    ],
)
def test_probe_sanitizes_and_classifies_failures(monkeypatch, failure, expected_note):
    def fail_client(*args, **kwargs):
        raise failure

    async def fake_resolve_public_ips(_domain):
        return ["8.8.8.8"]

    monkeypatch.setattr(main, "resolve_public_ips_async", fake_resolve_public_ips)
    monkeypatch.setattr(main.httpx, "AsyncClient", fail_client)

    result = asyncio.run(main.probe("example.com"))

    assert result["confidence"] == "unreachable"
    assert expected_note in result["notes"]
    assert "secret-hostname.internal" not in result["notes"]
    assert "10.0.0.7" not in result["notes"]
    assert "secret implementation detail" not in result["notes"]
    assert result["status_code"] is None
    assert result["php_indicator"] is False
    assert result["version_observed"] is None


@pytest.mark.parametrize("value", ["=1+1", "+SUM(A1:A2)", "-1+2", "@SUM(A1)", "  =1+1", "\t=1+1", "\r=1+1"])
def test_safe_csv_cell_neutralizes_formula_prefixes(value):
    from app.main import _safe_csv_cell

    safe = _safe_csv_cell(value)
    if value.startswith(("\\t", "\\r", "\\n")):
        # A leading control character is neutralized at the start of the cell.
        assert safe == "'" + value
    else:
        assert safe.endswith("'" + value.lstrip(" "))
    assert safe != value

@pytest.mark.parametrize("value", ["example.com", "PHP/8.3", "ordinary text", 0, 200, True, None])
def test_safe_csv_cell_preserves_non_formula_values(value):
    from app.main import _safe_csv_cell

    assert _safe_csv_cell(value) == value


def test_results_csv_streams_bounded_batches_without_fetchall(monkeypatch):
    class FakeCursor:
        def __init__(self):
            self.batches = [
                [("example.com", "2026-10-30T12:00:00+00:00", 200, "nginx", "PHP/8.3", True, "8.3", "version-disclosed", "ok")],
                [],
            ]
            self.fetch_sizes = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _query):
            pass

        def fetchmany(self, size):
            self.fetch_sizes.append(size)
            return self.batches.pop(0)

        def fetchall(self):
            raise AssertionError("CSV export must not call fetchall")

    class FakeConnection:
        def __init__(self):
            self.fake_cursor = FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self, name=None):
            assert name == "scanner_csv_export"
            return self.fake_cursor

    connection = FakeConnection()
    monkeypatch.setattr(main, "db_connect", lambda: connection)

    response = main.results_csv()

    async def collect_chunks():
        return [chunk async for chunk in response.body_iterator]

    chunks = asyncio.run(collect_chunks())
    csv_text = "".join(chunk.decode() if isinstance(chunk, bytes) else chunk for chunk in chunks)

    assert csv_text.startswith("domain,scanned_at,status_code")
    assert "example.com" in csv_text
    assert "PHP/8.3" in csv_text
    assert connection.fake_cursor.fetch_sizes == [500, 500]



def test_response_body_limit_stops_at_configured_byte_count():
    class FakeResponse:
        def __init__(self):
            self.yielded = 0

        async def aiter_bytes(self, chunk_size):
            assert chunk_size == 8192
            self.yielded += 1
            yield b"1234"
            self.yielded += 1
            yield b"5678"
            self.yielded += 1
            yield b"ignored"

    response = FakeResponse()
    consumed, truncated = asyncio.run(_read_response_body_limited(response, 5))

    assert consumed == 5
    assert truncated is True
    assert response.yielded == 2


def test_response_body_limit_accepts_body_at_exact_limit():
    class FakeResponse:
        async def aiter_bytes(self, chunk_size):
            yield b"123"
            yield b"45"

    consumed, truncated = asyncio.run(_read_response_body_limited(FakeResponse(), 5))

    assert consumed == 5
    assert truncated is False


def test_response_body_limit_rejects_negative_limit():
    class FakeResponse:
        async def aiter_bytes(self, chunk_size):
            yield b"unused"

    with pytest.raises(ValueError, match="must not be negative"):
        asyncio.run(_read_response_body_limited(FakeResponse(), -1))
