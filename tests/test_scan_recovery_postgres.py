"""SEC-15 PostgreSQL tests for crash recovery and sustained reservation churn."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import threading

from app import main


def _expire_slot(connect, slot_id):
    with connect() as conn:
        conn.execute(
            "UPDATE scan_slots SET lease_until=%s WHERE slot_id=%s",
            (datetime.now(timezone.utc) - timedelta(seconds=1), slot_id),
        )


def test_worker_crash_keeps_live_lease_then_recovers_expired_slot(postgres_reservations):
    # Simulate four workers reserving capacity. Worker 1 crashes without release.
    crashed_slot = main.reserve_scan_capacity(1)
    other_slots = [main.reserve_scan_capacity(domain_id) for domain_id in (2, 3, 4)]
    assert crashed_slot is not None
    assert all(slot is not None for slot in other_slots)

    # A fifth worker cannot steal a still-valid lease.
    assert main.reserve_scan_capacity(5) is None

    # Simulate lease expiry after the crashed worker has stopped heartbeating.
    _expire_slot(postgres_reservations, crashed_slot)
    recovered = main.reserve_scan_capacity(5)
    assert recovered == crashed_slot

    for slot in other_slots:
        main.release_scan_capacity(slot)
    main.release_scan_capacity(recovered)


def test_repeated_reserve_release_cycles_leave_all_slots_reusable(postgres_reservations):
    # Cycle across distinct domains so the per-domain cooldown does not mask
    # slot reuse. Twenty domains are provisioned by the shared fixture.
    granted = []
    for domain_id in range(1, 21):
        slot = main.reserve_scan_capacity(domain_id)
        assert slot is not None
        granted.append(slot)
        main.release_scan_capacity(slot)

    assert len(granted) == 20
    assert set(granted).issubset(set(range(1, main.MAX_CONCURRENT_SCANS + 1)))

    # After churn, all four slots can be acquired concurrently again.
    barrier = threading.Barrier(main.MAX_CONCURRENT_SCANS)

    def reserve(domain_id):
        barrier.wait(timeout=10)
        return main.reserve_scan_capacity(domain_id)

    with ThreadPoolExecutor(max_workers=main.MAX_CONCURRENT_SCANS) as pool:
        final_slots = list(pool.map(reserve, (1, 2, 3, 4)))

    assert all(slot is not None for slot in final_slots)
    assert len(set(final_slots)) == main.MAX_CONCURRENT_SCANS
    for slot in final_slots:
        main.release_scan_capacity(slot)


def test_expired_crashed_slot_is_recovered_under_concurrent_contention(postgres_reservations):
    crashed_slot = main.reserve_scan_capacity(1)
    assert crashed_slot is not None
    _expire_slot(postgres_reservations, crashed_slot)

    workers = 8
    barrier = threading.Barrier(workers)

    def reserve(domain_id):
        barrier.wait(timeout=10)
        return main.reserve_scan_capacity(domain_id)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        slots = list(pool.map(reserve, range(2, workers + 2)))

    granted = [slot for slot in slots if slot is not None]
    assert len(granted) == 1
    assert granted[0] == crashed_slot
    main.release_scan_capacity(granted[0])
