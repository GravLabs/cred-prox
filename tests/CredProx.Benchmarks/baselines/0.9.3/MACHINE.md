# Baseline run environment — 0.9.3

- Source: the release commit `d3896d0` (benchmarks and `src/` byte-identical to the
  published 0.9.3 library, which is itself byte-identical to 0.9.2 in `src/`; the
  release-pass record at `603dc5b` and this refresh pass gate to the same summary —
  the deltas between the two commits are text and gate-script only).
- Date: 2026-11-11, 14:57 → 15:00 UTC (BenchmarkDotNet global runs 2 m 08 s).
- OS: Linux, kernel 7.0.0-42-generic (Ubuntu 26.04.1 LTS), x86_64.
- CPU: Intel Core i9-10900KF @ 3.70 GHz, 10 physical / 20 logical cores.
- .NET SDK 10.0.115, .NET 10.0.15; BenchmarkDotNet 0.15.8.
- Job (pinned in `Program.cs`): LaunchCount 1, WarmupCount 5, IterationCount 15,
  IterationTime 250 ms.
- Load average: 0.35 / 0.54 / 0.58 before the pass, 0.81 / 0.97 / 0.80 after
  (20-logical-core machine; the machine also hosts ordinary desktop and container
  workloads, hence the same-run ratio gates in `scripts/bench-compare.sh`).
- Pre-bake gate vs the `0.9.2` baseline: 13 methods compared, FAIL=0 WARN=3 — all
  three warnings are warn-mode MEAN drifts in the overhead suite
  (OAuthCacheHitScrub x1.64, PlainYarp x1.69, StaticKeyAttach x1.85), the known
  shared-machine pattern. The allocation gate is green: every arm within its
  allowance, `TokenCacheBenchmarks.SingleFlight` 23,444 → 23,520 B, inside the
  measured 23,444–23,520 B scheduling band for that arm (`docs/benchmarks.md`).
- Files: for each suite the markdown report (`*-report-github.md`, human summary) and
  the full JSON (`*-report-full.json`, statistics and per-iteration measurements;
  what the comparison script parses).

Timing on this class of machine is shared-machine noise — the SSE and per-request
means carry double-digit percent error bars; allocations per operation are the stable,
deterministic signal. Percentiles are available per case in the JSON's Measurements
arrays (the markdown reports do not render percentile columns).

## Overhead suite re-capture (SSE workload change, M37 — 2026-11-14)

- Source: m37 commit `20c4f2c` — `src/` byte-unchanged from 0.9.3; only
  `OverheadBenchmarks.cs` changed: the SSE stub now echoes the credential-bearing
  headers into each event (so `SseCredProx` pays for real per-event redaction), the
  stream is bounded at three events, and `TimeToFirstEvent` asserts the first read
  starts with `data:`. That invalidated the two SSE baseline rows, so the Overhead
  suite was re-measured here (same pinned job, same machine, `--filter
  "*OverheadBenchmarks*"`, 01:44 UTC) and its JSON + markdown replace the 11-11
  ones. The other four suites in this directory are byte-identical to the 0.9.3 pass.
- Reference pass allocations: SsePlain 8,766 B, SseCredProx 14,469 B — roughly 1/8
  of the old 64,842 / 80,213 B, which counted ~5 s of writes against the abandoned
  connection; SSE means fell accordingly (149.6 / 201.4 µs).
- Second pass at the identical workload: SsePlain 7,230 B, SseCredProx 12,943 B.
  Five further pinned passes at the M37 fold (2026-11-14): SseCredProx 12,116 /
  14,435 / 13,784 / 15,989 / 14,437 B, SsePlain 8,116 / 7,292 / 7,399 / 8,551 /
  7,452 B — only `f2p1` of these six is a full 13-method pass, `f2p2`–`f2p5` are
  Overhead-only captures. Across all six passes the max UPWARD excursion over the reference is
  SseCredProx +1,520 B (10.5%); SsePlain never rose above its reference. The SSE
  `NOISY_ALLOC_FRACTION` therefore sits at 12%: an interim 25% set from the
  two-sample band was wider than the six-pass data supports, and the largest
  SseCredProx regression this allowance can still miss is +1,736 B (12% of the
  reference; +1,737 B is the smallest it catches). Because the bounded stream is small, the run-dependent count of
  buffered socket events is a larger SHARE of SSE allocation than before
  (evidence recorded in `docs/benchmarks.md`).
