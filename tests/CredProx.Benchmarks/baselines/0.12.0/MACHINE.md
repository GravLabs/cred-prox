# Baseline run environment — 0.12.0

- Source: main tip `0feb05a45fd7be6b49eccf8a2f4ee6961839423d` (bench branch `bench-0.12.0`).
  The src tree is identical to the internal release commit `682a676` — `git diff --stat
  682a676 0feb05a -- src` is empty (the delta to the main tip is docs and test-only commits);
  the public commit `5cc1a7e`'s tree equals `682a676`. The pass therefore measures exactly the
  published 0.12.0 library bytes.
- Date: 2026-11-18, 02:09 → 02:12 UTC (sum of the five suite run times: 1 min 54 s,
  13 benchmarks executed; suite run times 6.9 + 16.9 + 49.5 + 27.7 + 13.5 s).
- OS: Linux, kernel 7.0.0-42-generic (Ubuntu 26.04.1 LTS), x86_64.
- CPU: Intel Core i9-10900KF @ 3.70 GHz, 10 physical / 20 logical cores.
- .NET SDK 10.0.115, .NET 10.0.15; BenchmarkDotNet 0.15.8.
- Job (pinned in `Program.cs`): LaunchCount 1, WarmupCount 5, IterationCount 15,
  IterationTime 250 ms.
- Load average: 0.49 / 1.24 / 2.70 before the pass, 2.10 / 1.74 / 2.69 after
  (20-logical-core machine; it also hosts ordinary desktop and container workloads,
  hence the same-run ratio gates in `scripts/bench-compare.sh`).
- Refresh gate vs the `0.11.0` baseline: `13 methods compared, FAIL=3 WARN=0`
  (compare exit 1). The three FAILs are exactly the maintainer-accepted credential-attach
  arms — `OAuthCacheHit` 7,864 → 7,977 B (+113 B), `OAuthCacheHitScrub` 9,735 → 9,840 B
  (+105 B), `StaticKeyAttach` 7,457 → 7,574 B (+117 B) — each inside its arm's recorded
  spread of identical-code passes, +112…113, +105…108 and +111…128 B over six passes
  (docs/benchmarks.md, "Accepted release-delta
  allocations"); `StaticKeyAttach` also moved its same-run ratio ×1.51 and mean ×1.43,
  inside the documented echo-arm band. The other ten arms unchanged or inside their
  documented allowances, three of them rose: `SseCredProx`
  11,751 → 12,218 B inside its 12 % allowance (mean 236.53 → 133.57 µs), `SsePlain`
  9,035 → 9,931 B inside its allowance, `TokenCacheBenchmarks.SingleFlight` 23,457 →
  23,520 B (+63 B) inside `max(32 B, 1 %)`. `FAIL=3` here is the accepted release-delta
  cost, not a new regression. Statistics depth `N=13` on `OAuthCacheHit`, `N=14` on
  `OAuthCacheHitScrub`, `N=15` on the other eleven — all above the floor of 10.
- Gate extras at the same tree: full-solution Release build 0 Warning(s) / 0 Error(s);
  doc-snippet guards (`PackageReadmeTableTests`, `VendorSnippetValidationTests`) 21/21.
- This pass is the `0.12.0` release-record baseline. Raw artifacts (all four report
  formats per suite) are retained by the seat that ran the pass, not committed.
