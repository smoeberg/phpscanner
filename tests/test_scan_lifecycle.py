"""SEC-14 API lifecycle tests: timeout, probe failure and cancellation cleanup."""
import asyncio

import pytest
from fastapi import HTTPException

from app import main


class _Result:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class _Connection:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, *_args, **_kwargs):
        return _Result((7, "verified.example", object()))


@pytest.fixture
def scan_state(monkeypatch):
    releases = []
    monkeypatch.setattr(main, "db_connect", _Connection)
    monkeypatch.setattr(main, "reserve_scan_capacity", lambda _domain_id: (2, "test-lease-token"))
    monkeypatch.setattr(main, "release_scan_capacity", lambda slot, token: releases.append((slot, token)))
    return releases


def test_timeout_returns_504_and_releases_reservation(monkeypatch, scan_state):
    async def slow_probe(_domain):
        await asyncio.sleep(0.05)

    monkeypatch.setattr(main, "probe", slow_probe)
    monkeypatch.setattr(main, "SCAN_EXECUTION_DEADLINE_SECONDS", 0.001)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(main.scan_domain(7))

    assert exc.value.status_code == 504
    assert scan_state == [(2, "test-lease-token")]


def test_probe_exception_is_preserved_and_reservation_released(monkeypatch, scan_state):
    class ProbeFailure(RuntimeError):
        pass

    async def failing_probe(_domain):
        raise ProbeFailure("probe failed")

    monkeypatch.setattr(main, "probe", failing_probe)

    with pytest.raises(ProbeFailure, match="probe failed"):
        asyncio.run(main.scan_domain(7))

    assert scan_state == [(2, "test-lease-token")]


def test_task_cancellation_releases_reservation(monkeypatch, scan_state):
    async def run():
        started = asyncio.Event()

        async def waiting_probe(_domain):
            started.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(main, "probe", waiting_probe)
        task = asyncio.create_task(main.scan_domain(7))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert scan_state == [(2, "test-lease-token")]


def test_cleanup_failure_does_not_mask_timeout(monkeypatch):
    async def slow_probe(_domain):
        await asyncio.sleep(0.05)

    def failing_release(_slot, _token):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(main, "db_connect", _Connection)
    monkeypatch.setattr(main, "reserve_scan_capacity", lambda _domain_id: (2, "test-lease-token"))
    monkeypatch.setattr(main, "release_scan_capacity", failing_release)
    monkeypatch.setattr(main, "probe", slow_probe)
    monkeypatch.setattr(main, "SCAN_EXECUTION_DEADLINE_SECONDS", 0.001)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(main.scan_domain(7))

    assert exc.value.status_code == 504
