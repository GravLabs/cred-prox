# CredProx.LoadTests

The nightly load layer from `docs/credprox-plan.md` §5.1 "Load": real clocks, real
threads, sustained concurrency against the in-process pipeline. These tests assert
behavioral invariants under load, not throughput numbers:

- `ThrottleLoadTests` — a 200-request burst never pushes the upstream past the
  configured rate; the concurrency cap holds under contention.
- `CircuitBreakerLoadTests` — sustained failures open the cluster's circuit breaker and
  the open circuit sheds callers without touching the upstream; recovery closes it.
- `TokenCacheLoadTests` — five waves of 100 concurrent callers across five refresh
  cycles produce exactly five vendor fetches (single-flight holds under load).

Run:

```bash
dotnet test tests/CredProx.LoadTests -c Release
```

Deviation from the plan's "NBomber or k6": the §5.2 load assertions are invariants
(rate held, breaker opens/closes, single-flight kept), which plain xUnit load
generators express in the repo's existing test stack with no extra tooling or Docker
dependency on the nightly runner.

These tests use real timers and are timing-tolerant (generous bounds, invariant-based
assertions), but like any real-time test they belong to the nightly layer, not the
per-PR gate.
