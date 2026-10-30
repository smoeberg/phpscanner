"""Real-socket integration coverage for the DNS-pinned HTTPX transport."""
import asyncio
import socket
import ssl
import subprocess

import httpx
import pytest

from app.main import _pinned_transport


def _test_certificates(tmp_path, certificate_hostname):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-nodes", "-subj", f"/CN={certificate_hostname}",
            "-addext", f"subjectAltName=DNS:{certificate_hostname}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return cert, key


@pytest.mark.parametrize(
    ("certificate_hostname", "succeeds"),
    [("example.test", True), ("wrong.test", False)],
)
def test_pinned_transport_uses_real_peer_and_tls_hostname(
    tmp_path, monkeypatch, certificate_hostname, succeeds
):
    async def scenario():
        cert, key = _test_certificates(tmp_path, certificate_hostname)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        observed = {"sni": None, "peer": None, "host": None}

        def capture_sni(_sslobj, server_name, _context):
            observed["sni"] = server_name

        server_context.set_servername_callback(capture_sni)

        async def handle(reader, writer):
            observed["peer"] = writer.get_extra_info("peername")[0]
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                for line in request.decode("latin-1").split("\r\n"):
                    if line.lower().startswith("host:"):
                        observed["host"] = line.split(":", 1)[1].strip()
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    b"Connection: close\r\n\r\nok"
                )
                await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(
            handle, "127.0.0.1", 0, ssl=server_context
        )
        port = server.sockets[0].getsockname()[1]
        client_context = ssl.create_default_context(cafile=str(cert))
        original_getaddrinfo = socket.getaddrinfo
        target_lookups = []

        def guarded_getaddrinfo(host, *args, **kwargs):
            if str(host).lower().rstrip(".") == "example.test":
                target_lookups.append(host)
                raise AssertionError("Pinned connection attempted a second DNS lookup")
            return original_getaddrinfo(host, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
        transport = _pinned_transport(
            "example.test", "127.0.0.1", verify=client_context
        )
        try:
            async with httpx.AsyncClient(
                transport=transport,
                trust_env=False,
                follow_redirects=False,
                timeout=3.0,
            ) as client:
                if succeeds:
                    response = await client.get(f"https://example.test:{port}/")
                    assert response.status_code == 200
                else:
                    with pytest.raises(httpx.TransportError):
                        await client.get(f"https://example.test:{port}/")
        finally:
            server.close()
            await server.wait_closed()

        assert target_lookups == []
        assert observed["peer"] == "127.0.0.1"
        assert observed["sni"] == "example.test"
        if succeeds:
            assert observed["host"] == f"example.test:{port}"
        else:
            # TLS hostname validation fails before an HTTP request is sent.
            assert observed["host"] is None

    asyncio.run(scenario())
