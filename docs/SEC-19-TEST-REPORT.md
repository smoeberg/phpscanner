# SEC-19 test report: stalled-worker lease expiry and recovery

Baseline: `develop` at `2995a3d093ab1d0f0ca980b10506d2baa36e00c9`.

## Coverage added

- PostgreSQL timestamps, rather than host-clock calculations or sleeps, drive lease expiry in the recovery fixture.
- The lease boundary is tested directly: a future lease is not recoverable; a lease set to the database's current timestamp is recoverable because production selects `lease_until <= now()`.
- The stalled-worker interleaving uses independent PostgreSQL connections through the existing reservation API. Worker A retains a live probe while its lease expires; worker B reclaims the same slot with a different token; A then performs its stale release.
- The test checks the slot's actual fencing-token owner and counts current, unexpired database leases before and after A's stale release. A fifth reservation is denied while the four current leases are held.
- Probe activity is tracked separately from database leases, so the test does not conflate the two quantities.
- The existing deadline/lease assertion remains in place: the 60-second execution deadline is 30 seconds shorter than the 90-second slot lease.

## Invariant demonstrated

The implementation enforces **at most four current, unexpired PostgreSQL leases**. Fencing tokens prevent a stale worker from releasing a slot that has been reassigned.

The tests also demonstrate an important limit: if a worker is suspended or otherwise delayed beyond its lease while its probe remains active, another worker can recover that lease and start another probe. In that interleaving, five live probes can coexist while only four current leases exist. Therefore these tests do **not** prove a hard at-most-four-live-probes invariant under arbitrary process suspension. The 60/90-second deadline/lease margin protects the normal execution path, but lease fencing alone cannot stop an already-running external probe after lease expiry.

## Scope

Test and documentation changes only. No production behavior, scan authorization, probe behavior, deployment, or Athos changes.
