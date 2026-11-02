"""SEC-15 PostgreSQL tests for crash recovery and sustained reservation churn."""
from concurrent.futures import ThreadPoolExecutor
import threading

from app import main
from test_scan_capacity_postgres import postgres_reservations


def _expire_slot(connect, reservation):
    # Use PostgreSQL's clock so the test does not depend on host/database clock
    # synchronization or wall-clock sleeps.
    with connect() as conn:
        updated = conn.execute(
            """
            UPDATE scan_slots
            SET lease_until = now() - interval '1 second'
            WHERE slot_id = %s AND lease_token = %s
            """,
            reservation,
        )
        assert updated.rowcount == 1


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



def test_lease_expiry_boundary_uses_database_clock_without_sleep(postgres_reservations):
    reservations = [main.reserve_scan_capacity(domain_id) for domain_id in (1, 2, 3, 4)]
    assert all(reservation is not None for reservation in reservations)
    expiring = reservations[0]

    # A future lease must remain unavailable. Use a wide margin so scheduler
    # delays cannot make this assertion flaky.
    with postgres_reservations() as conn:
        conn.execute(
            """
            UPDATE scan_slots
            SET lease_until = now() + interval '1 hour'
            WHERE slot_id = %s AND lease_token = %s
            """,
            expiring,
        )
    assert main.reserve_scan_capacity(5) is None

    # Equality is the recovery boundary because production uses lease_until <= now().
    # Setting it to the database's transaction timestamp avoids sleeping.
    with postgres_reservations() as conn:
        conn.execute(
            """
            UPDATE scan_slots
            SET lease_until = now()
            WHERE slot_id = %s AND lease_token = %s
            """,
            expiring,
        )

    recovered = main.reserve_scan_capacity(5)
    assert recovered is not None
    assert recovered[0] == expiring[0]
    assert recovered[1] != expiring[1]

    with postgres_reservations() as conn:
        active_leases = conn.execute(
            """
            SELECT count(*)
            FROM scan_slots
            WHERE lease_until > now() AND lease_token IS NOT NULL
            """
        ).fetchone()[0]
    assert active_leases == main.MAX_CONCURRENT_SCANS

    main.release_scan_capacity(*recovered)
    for reservation in reservations[1:]:
        main.release_scan_capacity(*reservation)


def test_stalled_worker_can_overlap_recovered_worker_probe(postgres_reservations):
    """Prove the four-slot lease bound is not a hard live-probe bound after a stall."""
    worker_a = main.reserve_scan_capacity(1)
    assert worker_a is not None

    active = {"count": 0}
    active_lock = threading.Lock()
    probe_threads = []

    def start_blocked_probe():
        started = threading.Event()
        finish = threading.Event()

        def run_probe():
            with active_lock:
                active["count"] += 1
            started.set()
            try:
                finish.wait(timeout=10)
            finally:
                with active_lock:
                    active["count"] -= 1

        thread = threading.Thread(target=run_probe, daemon=True)
        thread.start()
        assert started.wait(timeout=5)
        probe_threads.append((thread, finish))
        return thread, finish

    def active_probe_count():
        with active_lock:
            return active["count"]

    _thread_a, finish_a = start_blocked_probe()
    worker_b = None
    other_workers = []
    try:
        # A's probe remains active while its database lease expires. B recovers
        # the same slot with a new fencing token and begins its own probe.
        _expire_slot(postgres_reservations, worker_a)
        worker_b = main.reserve_scan_capacity(2)
        assert worker_b is not None
        assert worker_b[0] == worker_a[0]
        assert worker_b[1] != worker_a[1]
        _thread_b, finish_b = start_blocked_probe()

        # Fill the other three slots and start three more probes.
        other_workers = [main.reserve_scan_capacity(domain_id) for domain_id in (3, 4, 5)]
        assert all(reservation is not None for reservation in other_workers)
        other_finishes = [start_blocked_probe()[1] for _ in other_workers]

        assert active_probe_count() == main.MAX_CONCURRENT_SCANS + 1

        with postgres_reservations() as conn:
            before_release = conn.execute(
                """
                SELECT count(*)
                FROM scan_slots
                WHERE lease_until > now() AND lease_token IS NOT NULL
                """
            ).fetchone()[0]
        assert before_release == main.MAX_CONCURRENT_SCANS

        # A's stale finally block must be a no-op: B still owns the slot and
        # no fifth current lease can be granted.
        main.release_scan_capacity(*worker_a)
        with postgres_reservations() as conn:
            current_owner = conn.execute(
                "SELECT lease_token FROM scan_slots WHERE slot_id = %s",
                (worker_b[0],),
            ).fetchone()[0]
            after_stale_release = conn.execute(
                """
                SELECT count(*)
                FROM scan_slots
                WHERE lease_until > now() AND lease_token IS NOT NULL
                """
            ).fetchone()[0]
        assert current_owner == worker_b[1]
        assert after_stale_release == main.MAX_CONCURRENT_SCANS
        assert main.reserve_scan_capacity(6) is None

        # Finish A. Four probes remain active and the four current leases are
        # still owned by B/C/D/E.
        finish_a.set()
        probe_threads[0][0].join(timeout=5)
        assert not probe_threads[0][0].is_alive()
        assert active_probe_count() == main.MAX_CONCURRENT_SCANS

        finish_b.set()
        for finish in other_finishes:
            finish.set()
    finally:
        for _thread, finish in probe_threads:
            finish.set()
        for thread, _finish in probe_threads:
            thread.join(timeout=5)
        if worker_b is not None:
            main.release_scan_capacity(*worker_b)
        for reservation in other_workers:
            if reservation is not None:
                main.release_scan_capacity(*reservation)

