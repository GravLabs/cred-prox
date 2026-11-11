# Baseline run environment — 0.9.2

- Source: detached worktree at the 0.9.2 public release commit (tree identical to
  the internal release commit); the measured code is the published 0.9.2 library.
- Date: 2026-11-10, 19:34 → 19:39 UTC.
- OS: Linux, kernel 7.0.0-42-generic (Ubuntu 26.04.1 LTS), x86_64.
- CPU: Intel Core i9-10900KF @ 3.70 GHz, 10 physical / 20 logical cores.
- .NET SDK 10.0.114; BenchmarkDotNet 0.15.8.
- Job (pinned in `Program.cs`): LaunchCount 1, WarmupCount 5, IterationCount 15,
  IterationTime 250 ms.
- Load average: 0.72 / 1.04 / 1.18 before the pass, 1.94 / 1.68 / 1.43 after
  (20-logical-core machine; the machine also hosts ordinary desktop and container
  workloads, hence the same-run ratio gates in `scripts/bench-compare.sh`).
- Pre-bake gate vs the `0.9.1` baseline: 13 methods compared, FAIL=0 WARN=4 — all
  four warnings are warn-mode TIMING ratios (OAuthCacheHitScrub, both SSE arms,
  StaticKeyAttach); both SSE arms inflated together (x1.37 and x1.53), i.e. shared
  loopback/streaming noise in this pass, not a CredProx regression. Every
  allocation figure is at or below its 0.9.1 sibling (SseCredProx 80.45 KB, inside
  the 75–83 KB band the release records).
- Files: for each suite the markdown report (`*-report-github.md`, human summary) and
  the full JSON (`*-report-full.json`, statistics and per-iteration measurements;
  what the comparison script parses).

Timing on this class of machine is shared-machine noise — the SSE and per-request
means carry double-digit percent error bars; allocations per operation are the stable,
deterministic signal. Percentiles are available per case in the JSON's Measurements
arrays (the markdown reports do not render percentile columns).
