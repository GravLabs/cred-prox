# Baseline run environment — 0.9.1

- Source: `main` at the 0.9.1 release tree; the measured code is the published 0.9.1
  library, with the benchmark harness of this branch around it.
- Date: 2026-11-10, 02:14 → 02:52 UTC.
- OS: Linux, kernel 7.0.0-42-generic (Ubuntu 26.04.1 LTS), x86_64.
- CPU: Intel Core i9-10900KF @ 3.70 GHz, 10 physical / 20 logical cores.
- .NET SDK 10.0.114; BenchmarkDotNet 0.15.8.
- Job (pinned in `Program.cs`): LaunchCount 1, WarmupCount 5, IterationCount 15,
  IterationTime 250 ms.
- Load average: 0.48 / 0.58 / 0.56 before the pass, 0.81 / 0.99 / 0.81 after
  (20-logical-core machine; the machine also hosts ordinary desktop and container
  workloads, hence the same-run ratio gates in `scripts/bench-compare.sh`).
- Files: for each suite the markdown report (`*-report-github.md`, human summary) and
  the full JSON (`*-report-full.json`, statistics and per-iteration measurements;
  what the comparison script parses).

Timing on this class of machine is shared-machine noise — the SSE and per-request
means carry double-digit percent error bars; allocations per operation are the stable,
deterministic signal. Percentiles are available per case in the JSON's Measurements
arrays (the markdown reports do not render percentile columns).
