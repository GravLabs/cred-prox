# Baseline run environment — 0.11.0

- Source: the post-release branch `post0110` at `ef9e19de163ae8b0a7d1f0c3b150ca7dcd72340a`,
  whose code tree is identical to the internal release commit `1fa3b6b` (the only diff is
  `docs/credprox-plan.md`). The published 0.11.0 library was packed from the public commit
  `f23938405d797f4dfc6564faaa7bdfb5dff2599a`, whose tree is identical to `1fa3b6b`.
- Date: 2026-11-16, 03:28 → 03:30 UTC (BenchmarkDotNet global run: 1 min 55 s,
  13 benchmarks executed).
- OS: Linux, kernel 7.0.0-42-generic (Ubuntu 26.04.1 LTS), x86_64.
- CPU: Intel Core i9-10900KF @ 3.70 GHz, 10 physical / 20 logical cores.
- .NET SDK 10.0.115, .NET 10.0.15; BenchmarkDotNet 0.15.8.
- Job (pinned in `Program.cs`): LaunchCount 1, WarmupCount 5, IterationCount 15,
  IterationTime 250 ms.
- Load average: 0.52 / 0.65 / 1.06 before the pass, 1.80 / 1.28 / 1.25 after
  (20-logical-core machine; it also hosts ordinary desktop and container workloads,
  hence the same-run ratio gates in `scripts/bench-compare.sh`).
- Refresh gate vs the `0.10.0` baseline: `13 methods compared, FAIL=0 WARN=5`
  (compare exit 0). All five WARNs are warn-mode checks on the overhead suite:
  `OAuthCacheHit` same-run ratio ×1.35; `OAuthCacheHitScrub` ratio ×2.38 and mean
  83.41 → 156.14 µs (×1.87); `SseCredProx` ratio ×1.55 and mean ×1.22 (allocations
  13,618 → 11,751 B, down); `SsePlain` ratio ×1.30 (allocations 9,960 → 9,035 B, down);
  `StaticKeyAttach` ratio ×1.67 and mean ×1.32 — all inside the documented loopback-HTTP
  echo-arm noise band (×1.6 – 2.8, `docs/benchmarks.md`). The allocation gate is green:
  deterministic arms flat or down, `TokenCacheBenchmarks.SingleFlight` 23,457 B inside
  its `max(32 B, 1 %)` allowance (+23 B over baseline). The WARN count moves pass to
  pass on this shared machine — `FAIL=0` is the stable signal (0.9.4/0.10.0 lineage).
- This pass is the `0.11.0` release-record baseline. Raw artifacts (all four report
  formats per suite) are retained by the seat that ran the pass, not committed.
