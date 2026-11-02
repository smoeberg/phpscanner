"""SEC-14 worker lifecycle tests: timeout, probe failure and cancellation cleanup."""
import asyncio

import pytest

from app import main, worker


class _Result:
    def fetchone(self):
        return ("verified.example", object())


class _Connection:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, *_args, **_kwargs):
        return _Result()


@pytest.fixture
def worker_state(monkeypatch):
    releases = []
    failures = []
    monkeypatch.setattr(main, "db_connect", _Connection)
    monkeypatch.setattr(main, "reserve_scan_capacity", lambda _domain_id: (2, "test-lease-token"))
    monkeypatch.setattr(
        main, "release_scan_capacity",
        lambda slot, token: releases.append((slot, token)),
    )
    monkeypatch.setattr(
        worker, "fail_job",
        lambda job_id, token, message, *, retry: failures.append(
            (job_id, token, message, retry)
        ),
    )
    return {"releases": releases, "failures": failures}


def test_timeout_fails_job_and_releases_reservation(monkeypatch, worker_state):
    async def slow_probe(_domain):
        await asyncio.sleep(0.05)

    monkeypatch.setattr(main, "probe", slow_probe)
    monkeypatch.setattr(main, "SCAN_EXECUTION_DEADLINE_SECONDS", 0.001)

    asyncio.run(worker.process_job((7, 7, 1, "job-token")))

    assert worker_state["failures"] == [
        (7, "job-token", "Scan execution deadline exceeded", True)
    ]
    assert worker_state["releases"] == [(2, "test-lease-token")]


def test_probe_exception_is_recorded_and_reservation_released(monkeypatch, worker_state):
    class ProbeFailure(RuntimeError):
        pass

    async def failing_probe(_domain):
        raise ProbeFailure("probe failed")

    monkeypatch.setattr(main, "probe", failing_probe)

    asyncio.run(worker.process_job((7, 7, 1, "job-token")))

    assert worker_state["failures"] == [
        (7, "job-token", "Scan execution failed; see worker logs", True)
    ]
    assert worker_state["releases"] == [(2, "test-lease-token")]


def test_task_cancellation_releases_reservation(monkeypatch, worker_state):
    async def run():
        started = asyncio.Event()

        async def waiting_probe(_domain):
            started.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(main, "probe", waiting_probe)
        task = asyncio.create_task(worker.process_job((7, 7, 1, "job-token")))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert worker_state["releases"] == [(2, "test-lease-token")]
    assert worker_state["failures"] == []


def test_cleanup_failure_does_not_mask_timeout(monkeypatch, worker_state):
    async def slow_probe(_domain):
        await asyncio.sleep(0.05)

    def failing_release(_slot, _token):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(main, "release_scan_capacity", failing_release)
    monkeypatch.setattr(main, "probe", slow_probe)
    monkeypatch.setattr(main, "SCAN_EXECUTION_DEADLINE_SECONDS", 0.001)

    asyncio.run(worker.process_job((7, 7, 1, "job-token")))

    assert worker_state["failures"] == [
        (7, "job-token", "Scan execution deadline exceeded", True)
    ]
