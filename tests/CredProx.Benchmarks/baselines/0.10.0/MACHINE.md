# Baseline run environment — 0.10.0

- Source: the release commit `6f247e0` (docs/comment-only delta from the prep commit
  `f84a116`, which carried the full measured test battery; the non-comment src/tests
  diff between them is empty). The published 0.10.0 library was packed from the
  public commit `3ba5264`, whose tree is identical to `6f247e0`.
- Date: 2026-11-15, 23:21 → 23:23 UTC (BenchmarkDotNet global run: 2 min 03 s,
  13 benchmarks executed).
- OS: Linux, kernel 7.0.0-42-generic (Ubuntu 26.04.1 LTS), x86_64.
- CPU: Intel Core i9-10900KF @ 3.70 GHz, 10 physical / 20 logical cores.
- .NET SDK 10.0.115, .NET 10.0.15; BenchmarkDotNet 0.15.8.
- Job (pinned in `Program.cs`): LaunchCount 1, WarmupCount 5, IterationCount 15,
  IterationTime 250 ms.
- Load average: 0.80 / 1.80 / 1.76 before the pass, 1.66 / 1.85 / 1.79 after
  (20-logical-core machine; it also hosts ordinary desktop and container workloads,
  hence the same-run ratio gates in `scripts/bench-compare.sh`).
- Pre-bake gate vs the `0.9.4` baseline: `13 methods compared, FAIL=0 WARN=3` —
  all three are warn-mode checks on the overhead suite: `OAuthCacheHit` same-run
  ratio ×1.19; `SseCredProx` same-run ratio ×1.44 (allocations 13,618 B, inside
  the 12 % allowance); `SsePlain` allocations 8,325 → 9,960 B, above its 12 %
  warn allowance and far below the 2.5× hard-FAIL — the M37 measurement records
  this arm as not allocation-deterministic (stream-abandon timing).
  `TokenCacheBenchmarks.SingleFlight` 23,434 B, inside its measured band
  (23,444 – 23,520 B at unchanged `src/`). A second quiet pass ~25 min earlier on
  the same commit printed `FAIL=0 WARN=5` with the same arms plus two warn-mode
  ratio drifts inside the documented echo-arm noise (×1.6 – 2.8); the WARN count
  on these arms moves pass to pass — `FAIL=0` is the stable signal.
