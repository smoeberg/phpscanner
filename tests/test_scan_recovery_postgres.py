"""SEC-15 PostgreSQL tests for crash recovery and sustained reservation churn."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import threading

from app import main
from test_scan_capacity_postgres import postgres_reservations


def _expire_slot(connect, slot_id):
    with connect() as conn:
        conn.execute(
            "UPDATE scan_slots SET lease_until=%s WHERE slot_id=%s",
            (datetime.now(timezone.utc) - timedelta(seconds=1), slot_id[0]),
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
    assert recovered[0] == crashed_slot[0]
    assert recovered[1] != crashed_slot[1]

    for slot in other_slots:
        main.release_scan_capacity(*slot)
    main.release_scan_capacity(*recovered)


def test_repeated_reserve_release_cycles_leave_all_slots_reusable(postgres_reservations):
    # Cycle across distinct domains so the per-domain cooldown does not mask
    # slot reuse. Twenty domains are provisioned by the shared fixture.
    granted = []
    for domain_id in range(1, 21):
        slot = main.reserve_scan_capacity(domain_id)
        assert slot is not None
        granted.append(slot)
        main.release_scan_capacity(*slot)

    assert len(granted) == 20
    assert {reservation[0] for reservation in granted}.issubset(set(range(1, main.MAX_CONCURRENT_SCANS + 1)))

    # Reset cooldown timestamps so this assertion isolates slot reuse.
    with postgres_reservations() as conn:
        conn.execute(
            "UPDATE scan_rate_limits SET last_scan_started_at=%s",
            (datetime.now(timezone.utc) - timedelta(seconds=main.SCAN_COOLDOWN_SECONDS + 1),),
        )

    # After churn, all four slots can be acquired concurrently again.
    barrier = threading.Barrier(main.MAX_CONCURRENT_SCANS)

    def reserve(domain_id):
        barrier.wait(timeout=10)
        return main.reserve_scan_capacity(domain_id)

    with ThreadPoolExecutor(max_workers=main.MAX_CONCURRENT_SCANS) as pool:
        final_slots = list(pool.map(reserve, (1, 2, 3, 4)))

    assert all(slot is not None for slot in final_slots)
    assert len({slot[0] for slot in final_slots}) == main.MAX_CONCURRENT_SCANS
    for slot in final_slots:
        main.release_scan_capacity(*slot)


def test_expired_crashed_slot_is_recovered_under_concurrent_contention(postgres_reservations):
    # Occupy the other three slots so contention is specifically for the
    # single slot abandoned by the crashed worker.
    crashed_slot = main.reserve_scan_capacity(1)
    assert crashed_slot is not None
    live_slots = [main.reserve_scan_capacity(domain_id) for domain_id in (2, 3, 4)]
    assert all(slot is not None for slot in live_slots)
    assert crashed_slot[0] not in [slot[0] for slot in live_slots]

    _expire_slot(postgres_reservations, crashed_slot)

    workers = 8
    barrier = threading.Barrier(workers)

    def reserve(domain_id):
        barrier.wait(timeout=10)
        return main.reserve_scan_capacity(domain_id)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        slots = list(pool.map(reserve, range(5, workers + 5)))

    granted = [slot for slot in slots if slot is not None]
    assert len(granted) == 1
    assert granted[0][0] == crashed_slot[0]
    assert granted[0][1] != crashed_slot[1]

    main.release_scan_capacity(*granted[0])
    for slot in live_slots:
        main.release_scan_capacity(*slot)



def test_stale_worker_release_cannot_clear_recovered_workers_lease(postgres_reservations):
    worker_a = main.reserve_scan_capacity(1)
    assert worker_a is not None
    _expire_slot(postgres_reservations, worker_a)

    worker_b = main.reserve_scan_capacity(2)
    assert worker_b is not None
    assert worker_b[0] == worker_a[0]
    assert worker_b[1] != worker_a[1]

    # Occupy the other three slots so capacity exhaustion proves B's lease
    # remains active after A's stale finally block.
    other_workers = [main.reserve_scan_capacity(domain_id) for domain_id in (3, 4, 5)]
    assert all(reservation is not None for reservation in other_workers)

    # A's finally block runs late. Its old token must not release B's lease.
    main.release_scan_capacity(*worker_a)
    assert main.reserve_scan_capacity(6) is None

    main.release_scan_capacity(*worker_b)
    for reservation in other_workers:
        main.release_scan_capacity(*reservation)
    worker_c = main.reserve_scan_capacity(7)
    assert worker_c is not None
    assert worker_c[0] == worker_b[0]
    assert worker_c[1] not in (worker_a[1], worker_b[1])
    main.release_scan_capacity(*worker_c)


def test_old_token_cannot_release_a_later_reservation_on_same_slot(postgres_reservations):
    first = main.reserve_scan_capacity(1)
    assert first is not None
    main.release_scan_capacity(*first)

    second = main.reserve_scan_capacity(2)
    assert second is not None
    assert second[0] == first[0]
    assert second[1] != first[1]
    other_workers = [main.reserve_scan_capacity(domain_id) for domain_id in (3, 4, 5)]
    assert all(reservation is not None for reservation in other_workers)

    main.release_scan_capacity(*first)
    assert main.reserve_scan_capacity(6) is None

    main.release_scan_capacity(*second)
    for reservation in other_workers:
        main.release_scan_capacity(*reservation)
    third = main.reserve_scan_capacity(7)
    assert third is not None
    main.release_scan_capacity(*third)
