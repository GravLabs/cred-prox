# Baseline run environment — 0.13.0

- Source: main tip `f46ca3dad14808fda3c54200ea4c419b325492f9` (bench branch `post-0.13.0`).
  The src tree is identical to the release merge `9b23040` — `git diff --stat
  9b23040 f46ca3d -- src` is empty (the delta to the main tip is the version and
  Central Package Management pin commits) — and `9b23040`'s src equals the release
  candidate `302219d` (`git diff --stat 302219d 9b23040 -- src` empty). The pass
  therefore measures exactly the published 0.13.0 library bytes.
- Date: 2026-11-19, 04:21 → 04:23 UTC. Driver wall 1 min 49 s (benchmark run plus
  the gate comparison; this run's console does not print per-suite seconds, so the
  record cites the driver wall instead of suite-time sums); 13 benchmarks executed.
- OS: Linux, kernel 7.0.0-42-generic (Ubuntu 26.04.1 LTS), x86_64.
- CPU: Intel Core i9-10900KF @ 3.70 GHz, 10 physical / 20 logical cores.
- .NET SDK 10.0.115, .NET 10.0.15; BenchmarkDotNet 0.15.8.
- Job (pinned in `Program.cs`): LaunchCount 1, WarmupCount 5, IterationCount 15,
  IterationTime 250 ms.
- Load average: 1.03 / 3.16 / 3.06 before the pass, 1.55 / 2.74 / 2.92 after
  (20-logical-core machine; it also hosts ordinary desktop and container workloads,
  so the pass waited for the 1-minute load below 1.5 twice in a row before launching
  and the same-run ratio gates in `scripts/bench-compare.sh` cover the rest).
- Refresh gate vs the `0.12.0` baseline: `13 methods compared, FAIL=0 WARN=2`
  (compare exit 0). Both WARNs are warn-mode timing-only arms with *lower*
  allocations than 0.12.0: `OAuthCacheHitScrub` same-run ratio 1.216 → 1.492
  (×1.23), mean 83.01 → 106.47 µs (×1.28), alloc 9,840 → 9,731 B; `SseCredProx`
  ratio 1.956 → 3.376 (×1.73), mean 133.57 → 240.98 µs (×1.80), alloc
  12,218 → 12,062 B — both inside the documented noise bands
  (docs/benchmarks.md). The three credential-attach arms recover to their
  pre-0.12.0 allocations — `OAuthCacheHit` 7,977 → 7,864 B, `OAuthCacheHitScrub`
  9,840 → 9,731 B, `StaticKeyAttach` 7,574 → 7,457 B — reversing the
  +113/+105/+117 B accepted with 0.12.0 ("Accepted release-delta allocations").
  `SsePlain` alloc 9,931 → 7,267 B, `SingleFlight` 23,520 → 23,448 B; every
  other arm flat or better. Statistics depth `N=15` on ten arms, `N=14` on
  `SingleFlight`, `N=13` on `PlainYarp` and `StaticKeyAttach` — all above the
  floor of 10.
- Gate extras at the same tree: full-solution Release build 0 Warning(s) /
  0 Error(s); doc guards (`PackageReadmeTableTests`, `VendorSnippetValidationTests`,
  `SamplesReadmeOutputGuardTests`, `SamplesCiWiringTests`, `FuzzMatrixCorpusGuardTests`)
  29/29.
- This pass is the `0.13.0` release-record baseline. Raw artifacts (all four report
  formats per suite) are retained by the seat that ran the pass, not committed.
