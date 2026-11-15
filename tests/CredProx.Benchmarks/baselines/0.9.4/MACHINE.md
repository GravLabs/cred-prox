# Baseline run environment — 0.9.4

- Source: the release commit `8df333c` (`src/` and the benchmark code byte-identical
  to the prep commit `0c0fbc1`, the release-record pass commit; the delta between
  them is CHANGELOG text only). The published 0.9.4 library was packed from the
  public commit `ca814c7`, whose tree is identical to `8df333c`.
- Date: 2026-11-15, 05:23 → 05:25 UTC (BenchmarkDotNet global runs ≈ 2 min).
- OS: Linux, kernel 7.0.0-42-generic (Ubuntu 26.04.1 LTS), x86_64.
- CPU: Intel Core i9-10900KF @ 3.70 GHz, 10 physical / 20 logical cores.
- .NET SDK 10.0.115, .NET 10.0.15; BenchmarkDotNet 0.15.8.
- Job (pinned in `Program.cs`): LaunchCount 1, WarmupCount 5, IterationCount 15,
  IterationTime 250 ms.
- Load average: 0.84 / 0.82 / 1.51 before the pass, 1.36 / 1.11 / 1.51 after
  (20-logical-core machine; the machine also hosts ordinary desktop and container
  workloads, hence the same-run ratio gates in `scripts/bench-compare.sh`).
- Pre-bake gate vs the `0.9.3` baseline: 13 methods compared, FAIL=0 WARN=2 — both
  warnings are warn-mode MEAN drifts in the overhead suite (OAuthCacheHitScrub
  x1.29, PlainYarp x1.72), the known shared-machine pattern. The allocation gate
  is green: every arm within its allowance, `SseCredProx` 13,117 B (baseline
  14,469 B, allowance +1736 B), `TokenCacheBenchmarks.SingleFlight` 23,449 B,
  inside the measured 23,444–23,520 B scheduling band for that arm
  (`docs/benchmarks.md`).
- Files: for each suite the markdown report (`*-report-github.md`, human summary) and
  the full JSON (`*-report-full.json`, statistics and per-iteration measurements;
  what the comparison script parses).

Timing on this class of machine is shared-machine noise — the SSE and per-request
means carry double-digit percent error bars; allocations per operation are the stable,
deterministic signal. Percentiles are available per case in the JSON's Measurements
arrays (the markdown reports do not render percentile columns).
