# Baseline run environment — 0.15.0

- Source: measured detached at `ce99f5df334a92b66c922b22ef62405c3d1432d7`, `PORCELAIN=0` —
  the tree the 0.15.0 packages were built and published from (registry-only publish).
  This baseline commit sits on branch `post-0.15.0` over main `d7fd1cf`, and
  `git diff --name-only ce99f5d d7fd1cf -- src tests` is empty, so the committed tree
  measures exactly the published 0.15.0 library bytes. The driver header printed
  `TIP=ce99f5df334a92b66c922b22ef62405c3d1432d7 PORCELAIN=0`.
- Date: 2026-11-21, 13:43:55 → 13:45:44 UTC. Driver wall 1 min 49 s; 13 benchmarks
  executed across 5 suites (Overhead 6, Destination 2, TokenCache 2, Preset 2,
  AuditRedactor 1).
- OS: Linux, kernel 7.0.0-42-generic (Ubuntu 26.04.1 LTS Resolute Raccoon), x86_64.
- CPU: Intel Core i9-10900KF @ 3.70 GHz, 10 physical / 20 logical cores.
- .NET SDK 10.0.115, .NET 10.0.15; BenchmarkDotNet 0.15.8.
- Job (pinned in `Program.cs`): LaunchCount 1, WarmupCount 5, IterationCount 15,
  IterationTime 250 ms.
- Load average: 0.72 / 1.62 / 1.90 before the pass, 1.84 / 1.84 / 1.96 after
  (20-logical-core machine; it also hosts ordinary desktop and container workloads,
  so the pass waited for the 1-minute load below 1.5 twice in a row before launching
  — the quiet gate logged 0.93 — and the same-run ratio gates in
  `scripts/bench-compare.sh` cover the rest).
- Refresh gate vs the `0.13.0` baseline: `13 methods compared, FAIL=0 WARN=4`
  (compare exit 0). All four WARNs sit in warn-mode territory as documented in
  `docs/benchmarks.md`. Timing-only: `OAuthCacheHit` mean 82.14 → 132.73 µs (×1.62)
  and `PlainYarp` mean 71.37 → 121.86 µs (×1.71) — same-run ratio noise on this
  suite reaches ×2.8, and the absolute-mean arms warn without failing. SSE arms:
  `SseCredProx` alloc 12,062 → 14,373 B (1.19× baseline) and `SsePlain`
  7,267 → 9,991 B (1.38×) — these two arms are warn-only by design (the +12% line
  fires on their scatter alone; above 2.5× is the only stop), and `SseCredProx`
  sits inside the recorded base-side scatter span. `SsePlain` reads above its
  2026-11-14 pinned scatter record (7,292–8,551 B) while both SSE arms rose
  2.3–2.7 KB together across the 0.13.0 → 0.15.0 span; flagged here for the
  narrow re-check run against this baseline. Flat arms hold: `SingleFlight`
  23,520 B at the top of its documented band 23,444–23,520 B; `OAuthCacheHitScrub`
  +30 B inside the +27…35 B band accepted with the M45 security window; every
  other arm +0…+8 B. The `Statistics.N` floor check (10) fired on no arm
  (`OAuthCacheHitScrub` N=13, all other printing arms N=15).
- Gate extras at the same tree: the bench project built Release `0 Warning(s) /
  0 Error(s)` at `ce99f5d` before the pass. The full gate battery (full-solution
  build 0 Warning(s) / 0 Error(s), 2206/2206 tests, coverage ×3, six-package pack
  with APICompat clean and the version stamp, 86/86 sample smokes) ran at the
  round-4 candidate `4df03f1`; the tree identity of the src/tests/samples subtree
  from `4df03f1` to `ce99f5d` was verified by the checker
  (`FENCED_DELTA_LINES=0`), so those gates carry to the measured tree.
- This pass is the `0.15.0` release-record baseline for four of the five
  suites: this folder is mixed by design — four suites from this 13:43 pass
  (`TIP=ce99f5df334a92b66c922b22ef62405c3d1432d7`) and the Overhead pair from
  the 14:02 re-pin pass (`TIP=cf344b6445c2b9eb22a919e3735c89b7fbddf169`),
  documented at the end of this file — legitimate because `src` and `samples`
  are identical between those two trees, only the version metadata moved —
  the refresh that the 0.15.0 record required in place of the stale
  `0.13.0` base. Raw artifacts (all four
  report formats per suite) are retained by the seat that ran the pass, not
  committed; the compare log is kept in the seat's gate directory.

## Re-pin of the Overhead suite — 2026-11-21, 14:00:04 → 14:02:27 UTC

The checker's independent quiet-gated re-measure at the measured tree read
`SsePlain` at 7,454 B, inside the 2026-11-14 pinned record (7,292–8,551 B),
whereas this file's 13:43 pass had committed 9,991 B above it. A base that
high makes the `SsePlain` gate arm lenient, so the lead directed one fresh
Overhead-only quiet pass whose full `json` + `github` pair replaces the
committed Overhead report pair, so that all six arms come from one run. The
other four suites keep the 13:43 capture, unchanged.

- New pass driver header: `TIP=cf344b6445c2b9eb22a919e3735c89b7fbddf169
  PORCELAIN=0 @ 2026-11-21T14:00:04Z`; quiet gate satisfied twice in a row on
  the third 30 s check; `LOAD-AT-START=0.81 1.00 1.31`, `LOAD-AFTER=2.02 1.29
  1.40`; `RUN-RC=0`; one full `json` + one `github` report;
  `BENCH-DONE @ 2026-11-21T14:02:27Z`.
- Red-route disclosure: the first re-pin capture (13:57 pass, retained in the
  seat gate directory as `bench-r6a` + `results-r6a-1357/`) read `SsePlain`
  7,901 B inside the pinned record but printed `OAuthCacheHitScrub` +36 B
  against the flat +32 B allowance (+6 B above this file's 13:43 reading on
  the same tree: 9,767 vs 9,761 B). Per the documented red route exactly one quiet re-run was made;
  the numbers below are that second pass, kept as measured, with no tuning.
- Re-pin gate vs the `0.13.0` baseline (partial-suite route, Overhead only):
  `6 methods compared, FAIL=0 WARN=6` — four WARNs are the not-gated absent
  suites, two are timing-only same-run-ratio warns inside the documented
  envelope (`OAuthCacheHit` mean ×1.53, `StaticKeyAttach` mean ×1.67). Arms:
  `SsePlain` 7,267 → 7,230 B, `SseCredProx` 12,062 → 11,977 B, `PlainYarp`
  5,681 → 5,680 B, `StaticKeyAttach` 7,457 → 7,456 B, `OAuthCacheHit`
  7,864 → 7,864 B, `OAuthCacheHitScrub` 9,731 → 9,760 B (+29 B, inside the
  +27…35 B band accepted with the M45 security window).
- Recorded deviation, kept as measured: `SsePlain` 7,230 B lands 62 B below
  the 2026-11-14 pinned record floor (7,292 B) and `SseCredProx` 11,977 B
  lands 139 B below its recorded floor (12,116 B). Both deviations are on the
  low side, which makes the gate stricter rather than lenient. `SseCredProx`
  in particular is the low tail of four readings of this same tree — 11,977 B
  here (14:02), 14,373 B (13:43), 14,258 B (13:57) and 14,845 B (independent
  re-measure), three of them clustered around the 14,469 B reference — so the
  committed base's own warn line (13,414 B) sits below three of the four: a
  `SseCredProx` WARN against the `0.15.0` base is the expected outcome of an
  ordinary pass, not a regression to chase. The same clause is added to the
  SSE noise row in `docs/benchmarks.md`. The two
  report files committed with this section (the `github` table and the full
  `json`, same run, same environment block) are the base for the next
  release's Overhead comparisons.
