"""Adversarial regression tests for DNS validation and pinned outbound sockets."""

import asyncio
import socket

import httpcore
import pytest

from app import main


def _addrinfo(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 0, 0, 0) if family == socket.AF_INET6 else (address, 0)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
    ],
)
def test_dns_validation_rejects_non_global_address_classes(address):
    with pytest.raises(RuntimeError, match="ikke-offentlig IP"):
        main._validate_public_ips([_addrinfo(address)])


def test_dns_validation_rejects_scoped_link_local_ipv6():
    with pytest.raises(RuntimeError, match="ikke-offentlig IP"):
        main._validate_public_ips([_addrinfo("fe80::1%eth0")])


def test_dns_validation_rejects_mixed_public_and_private_answers():
    # A single unsafe A/AAAA answer invalidates the entire hostname. It must
    # not be made safe by sorting or selecting only the public answer.
    answers = [_addrinfo("8.8.8.8"), _addrinfo("2001:db8::1")]

    with pytest.raises(RuntimeError, match="ikke-offentlig IP"):
        main._validate_public_ips(answers)


def test_dns_validation_returns_deduplicated_sorted_global_addresses():
    answers = [
        _addrinfo("8.8.4.4"),
        _addrinfo("1.1.1.1"),
        _addrinfo("8.8.4.4"),
    ]

    assert main._validate_public_ips(answers) == ["1.1.1.1", "8.8.4.4"]


def test_pinned_backend_connects_to_configured_ip_not_requested_hostname():
    class RecordingBackend:
        def __init__(self):
            self.arguments = None

        async def connect_tcp(self, host, port, **kwargs):
            self.arguments = (host, port, kwargs)
            return "connected"

    backend = main._PinnedNetworkBackend("example.com", "8.8.8.8")
    recorder = RecordingBackend()
    backend._backend = recorder

    result = asyncio.run(
        backend.connect_tcp(
            b"example.com",
            443,
            timeout=3.0,
            local_address=None,
            socket_options=None,
        )
    )

    assert result == "connected"
    assert recorder.arguments[0:2] == ("8.8.8.8", 443)
    assert recorder.arguments[2] == {
        "timeout": 3.0,
        "local_address": None,
        "socket_options": None,
    }


def test_pinned_backend_rejects_a_different_requested_hostname():
    class ForbiddenBackend:
        async def connect_tcp(self, *_args, **_kwargs):
            raise AssertionError("A mismatched hostname must never reach the socket backend")

    backend = main._PinnedNetworkBackend("example.com", "8.8.8.8")
    backend._backend = ForbiddenBackend()

    with pytest.raises(httpcore.ConnectError, match="Unexpected destination host"):
        asyncio.run(backend.connect_tcp(b"internal.example", 443))


def test_pinned_backend_rejects_unix_socket_destinations():
    backend = main._PinnedNetworkBackend("example.com", "8.8.8.8")

    with pytest.raises(httpcore.ConnectError, match="Unix sockets are not permitted"):
        asyncio.run(backend.connect_unix_socket("/var/run/docker.sock"))
