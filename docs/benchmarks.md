# Benchmarks and regression tracking

CredProx sits in the hot path of every vendor call, so its cost per request is part
of the product. This page documents how that cost is measured, what the committed
baselines mean, and how `scripts/bench-compare.sh` turns a new run into a
pass/fail verdict.

## Suites

All suites live in `tests/CredProx.Benchmarks` (BenchmarkDotNet).

| Suite | What it measures |
|---|---|
| `OverheadBenchmarks` | The headline: the same loopback HTTP request through **plain YARP** versus through **CredProx**, against one in-process stub upstream on real Kestrel loopback sockets. Arms: plain baseline, static-key header attach, OAuth client-credentials on a warm token cache, the same plus response scrubbing (the production default), and SSE time-to-first-event plain versus CredProx. The plain arm is the benchmark baseline, so the report's ratios are the per-request overhead **within the same run**. |
| `TokenCacheBenchmarks` | The token-cache hit path (nanoseconds, zero allocation) versus a single-flight cache miss. |
| `DestinationBenchmarks` | Destination registry lookup and address-template expansion. |
| `AuditRedactorBenchmarks` | Redaction of a sensitive value from a log message. |
| `PresetBenchmarks` | Host composition cost with and without preset registration. |

## Running

```bash
dotnet run -c Release --project tests/CredProx.Benchmarks -- --filter "*"
```

Results land in `BenchmarkDotNet.Artifacts/results/` — relative to wherever the run
command executes, the repository root for the command below: a GitHub-markdown report and a
full JSON per suite. The job (1 launch, 5 warm-up, 15 × 250 ms iterations) is pinned
in `Program.cs` so the committed baseline and every comparison run execute under
identical settings. A full pass takes roughly 3–5 minutes; run it only when the
machine is quiet (`uptime` below ~1.5 on this 20-core box, no other builds or loads
running) — numbers taken while the machine is busy are garbage.

## Reading the results

Absolute times on a shared machine carry large error bars — the per-request HTTP
means move by tens of percent run to run purely from scheduling and CPU frequency
behaviour. Two numbers are trustworthy:

- **Allocated bytes per operation** — deterministic, quoted in every report.
- **Same-run ratio** — each arm divided by the suite's baseline arm within one run.

Percentiles (P95 included) are per case in the JSON's `Statistics.Percentiles`.

On a shared machine the overhead suite is in practice an **allocation gate**: its
ratio resolution is about 16 µs (×1.15 of the plain-YARP mean), so latency regressions are caught by the micro
suites, and a same-run ratio below 1.0 is noise, not a win.

## Measured noise (basis for the gates)

Unchanged-code reruns on the shared development machine, 2026-11:

| Signal | Observed drift across unchanged reruns |
|---|---|
| Overhead suite, same-run ratio (echo arms) | ×1.6 – ×2.8 |
| Overhead suite, same-run ratio (SSE arms) | ×1.6 – ×1.8 |
| Overhead suite, absolute mean | up to ±45% |
| Overhead suite, allocations (echo arms) | ≤ 7 B (≤0.1%) |
| Overhead suite, allocations (SSE arms, 3-event bounded stream) | Six pinned passes at unchanged workload (2026-11-14, after the M37 workload change): SseCredProx 12,116–15,989 B around the 14,469 B reference — max upward excursion +1,520 B (10.5%); SsePlain 7,292–8,551 B vs the 8,766 B reference, never above it. At the 12% allowance the largest SseCredProx regression the gate can still miss is +1,736 B (+1,737 B is the smallest it catches) (the old ~5 s abandoned stream measured +3.3% / +5.6% of much larger values). Interleaved A/B attribution (2026-11-15, six quiet-gated passes, the released 0.9.4 commit against the 0.10.0 candidate): the RELEASED code itself measured 14,434–16,578 B against the 13,117 B 0.9.4 reference while the candidate reached 25,567 B (1.95×) with none of the changed code in the arm's path — both trees exceeded the +12% line in 2 of 3 passes, so a fixed 12% FAIL cannot gate these arms |
| Micro suites, same-run ratio | ≤ ×1.13 (worst: the sub-microsecond destination arms — nanosecond-scale measurements against nanosecond-scale denominators) |
| Micro suites, absolute mean | ≤ +2.1% (except arms below ~100 ns, which track the ratio) |
| Micro suites, allocations | ≤ 16 B — **except** `TokenCacheBenchmarks.SingleFlight`: band 23,444 – 23,520 B (≈76 B) at unchanged `src/` |

The SSE arms abandon a live stream mid-read, so the number of buffered socket
events per operation varies slightly with timing — their allocations are not fully
deterministic. `SingleFlight` runs 64 concurrent waiters on a cold key, so each
operation also pays for BCL continuation objects whose count depends on
inline-vs-scheduled completion: unchanged-src reruns measured 23,444 / 23,481 /
23,500 / 23,520 B (2026-11-11). Everything else on the list is deterministic.

## The gate: `scripts/bench-compare.sh`

```bash
scripts/bench-compare.sh tests/CredProx.Benchmarks/baselines/0.9.3 \
    BenchmarkDotNet.Artifacts/results
```

Exits non-zero on a regression. Per method:

| Check | Overhead suite | Micro suites |
|---|---|---|
| Allocated bytes/op | FAIL above +32 B (SSE arms: above +12% **WARN**, hard FAIL above 2.5× the baseline allocation) | FAIL above +32 B (`SingleFlight`: max(32 B, 1% of baseline)) |
| Same-run ratio rise | WARN above ×1.15 (noise reaches ×2.8 — a fail-gate there would be theatre) | WARN above ×1.15, **FAIL** above ×1.25 (worst observed unchanged drift ×1.13 — the warn threshold sits above it) |
| Absolute mean rise | WARN above ×1.15 | WARN above ×1.15 |
| New-run `Statistics.N` below `N_FLOOR` (10) | WARN | WARN |

The allocation allowance is per-arm. An arm gets a proportional allowance only on
MEASURED scheduling noise with evidence in "Measured noise" above — never to make a
release pass. The key is the exact `(suite, method)` pair in `NOISY_ALLOC_FRACTION`
(never a substring or whole-suite match) and the fraction multiplies the BASELINE
allocation. Every other arm keeps the flat 32 B: the flat epsilon is the default,
never the proportional one. The applied allowance is printed on every gated arm as
`[allow ...]`.

The two SSE arms are warn-only above their allowance and hard-FAIL above 2.5× the
baseline allocation (`GROSS_ALLOC_FAIL_MULT`, keyed by the same exact
`(suite, method)` pair): the 2026-11-15 interleaved A/B attribution above shows the
released code failing its own +12% FAIL at the same rate as the candidate (2 of 3
passes in both trees): scheduling noise alone reaches 1.26× — the released-code
control's own maximum (16,578 B) — and the observed candidate tail reaches 1.95×,
so a FAIL there cannot identify a code change. A gross regression (buffering the stream end to end,
a scrub blow-up) lands above 2.5× and still FAILs. Every other arm is unchanged:
the flat 32 B stays a hard FAIL and so does `SingleFlight`'s max(32 B, 1%).

The comparison key is `(suite class, method, Parameters)`: `[Params]`/`[Arguments]`
rows stay distinct arms instead of silently collapsing into one, and the suite
baseline-arm check runs once per parameter set present in either tree. A report row
duplicated in title AND parameters makes the key ambiguous (JSON order would decide
which row wins) — the gate FAILs on it and never partial-downgrades it.

Every `ok` line prints the arm's N and P95 (`µs`, `n/a` when BDN wrote no
percentiles) so a quiet pass still shows what the verdict rested on; an arm whose
new-run `Statistics.N` is below `N_FLOOR` (default 10) WARNs — a thin sample cannot
support the statistics the gate reads. The floor gates the new run only: the
committed baseline passed review once. A `RATIO-SKIPPED` arm — its same-run ratio
uncomputable because the suite's baseline arm is missing or unusable (which itself
FAILs below) — also counts: FAIL in fail-mode suites, WARN in warn-mode ones, so the
summary line can never read clean while a timing gate sat out.

Overrides: `EPS_ALLOC`, `EPS_ALLOC_PCT` (explicit: re-fractions every proportional
arm; the value is a FRACTION of the baseline — `0.08` allows 8%, `1` allows 100%;
unset: the per-arm fractions above; never touches flat arms), `RATIO_WARN`, `RATIO_FAIL`, `MEAN_WARN`,
`N_FLOOR` (statistics-count warn floor, default 10), `ALLOW_PARTIAL=1` (accept a
partial run, loudly), and `TIMING_MODE=fail|warn` to
force one mode for all suites — for example on a dedicated benchmarking machine,
where tightening the overhead timing gate becomes reasonable (see "A quieter
machine" below). The script refuses to start (exit 2) when `RATIO_WARN` ≥
`RATIO_FAIL`: inverted thresholds would put the warn above the fail, making the
timing FAIL unreachable.

A method or suite present in the baseline but absent from the new run **FAILS** —
a lost or renamed arm is a regression, not a gap in the report. To gate a single
suite, either point both arguments at directories holding the same single suite's
baseline JSON (the gate then covers exactly that suite), or run against the full
baseline with `ALLOW_PARTIAL=1`, which downgrades the missing suites and methods to
loud warnings for a deliberate partial pass. A suite's baseline arm missing on
either side always FAILs: without its denominator the suite cannot gate timing.
With `ALLOW_PARTIAL=1`, a run that compares ZERO methods FAILs — partial still has
to mean some coverage; an empty results directory is not a partial pass. A no-statistics
arm fails the same way: the SSE framing/redaction assertion throws inside the benchmark,
which makes that BenchmarkDotNet arm NA while `dotnet run` itself still exits 0 —
`bench-compare` catches it because an arm without statistics FAILs even with
`ALLOW_PARTIAL=1`.

Known blind spots: the same-run ratio is blind to a slowdown of the *baseline* arm
itself (plain YARP getting slower makes CredProx look better) — the absolute-mean
WARN catches most of that, and allocation checks are unaffected. And single-arm
suites (`AuditRedactorBenchmarks`) have no ratio gate at all: their only method is
their own baseline arm, so the ratio is 1.000→1.000 by construction and only the
allocation check and the never-failing absolute-mean WARN guard them.

A deliberate 8 KB per-request allocation on a hot arm and a 1 ms delay on a hot
micro method were each caught by the gate during development of the script
(sabotage probes, not committed behaviour).

## Accepted release-delta allocations — 0.12.0

The 0.12.0 release-gate pass (against `baselines/0.11.0`, prep commit
`e10f18c0a622d75c3af6313d2d75cc9234c2f25c`, 2026-11-18 UTC) compared 13 methods with
`FAIL=3`. The three failures are the credential-attach arms, each beyond the flat
+32 B allowance:

| Arm | 0.11.0 baseline | 0.12.0 prep | Delta |
| --- | ---: | ---: | ---: |
| `OAuthCacheHit` | 7,864 B | 7,976 B | +112 B |
| `OAuthCacheHitScrub` | 9,735 B | 9,843 B | +108 B |
| `StaticKeyAttach` | 7,457 B | 7,575 B | +118 B |

Six passes on identical code (four full runs, two runs of just these three arms)
measured `OAuthCacheHit` at +112…113 B and `OAuthCacheHitScrub` at +105…108 B, but
`StaticKeyAttach` anywhere from +111 to +128 B, so that arm's allocation varies by up
to 17 B between runs: wider than the echo-arm band in the table above, and not
explained by anything measured so far. The drift itself is real in every pass and
belongs to the release delta
between `0.11.0` and `0.12.0` — chiefly the package-split seams, not the prep
commits — and the other ten methods measured unchanged, inside their documented allowances, or better. The maintainer
accepted the ~1.5% per-request allocation as the measured cost of the split for this
release: the priority for it is the minimal core, not a byte budget. Root-causing
which part of the split carries the +105…128 B, and why `StaticKeyAttach` varies, sits on the backlog and remains open
as of 0.12.0, not in the release; the baseline rotates to the `0.12.0` bytes at the
post-publish refresh below.

### The carried allocation found and removed (post-0.12.0)

A first-parent bisect of `0.11.0..0.12.0` on the `StaticKeyAttach` allocation later
located the drift in one commit, `160460d`: the measured-body hand-off installed a
delegate — a display class plus an `Action<byte[]>` — on every CredProx-routed
request, whether or not anything measures a body, and every attach-arm request paid
it (the live endpoints of that bisect straddled the committed baselines to ±5 B).
The hand-off shape now travels as a flag on the request state and the rewrite lives
inside `MeasureOutgoingBodyAsync`, so nothing is built per request; the bytes
flowing onward are unchanged. `0.12.0` itself shipped carrying the allocation — the
section above stands as the record of what was accepted and why. A structural pin in
the core battery (`CredProxRequestStateShapeTests`) fails if a delegate-typed instance
field rides `CredProxRequestState` again — exactly the shape `160460d` installed — and
every attach arm routes through that state, so one check stands in for all three arms.
A per-request closure created and invoked inline elsewhere on the transform path stays
green here; the out-of-process bench gate is its numeric net. Why `StaticKeyAttach`
varied by up to 17 B between gate passes stayed unexplained.

## Refreshing the baseline at each release

1. Run a full pass on a quiet machine against the release commit (see above).
2. Copy the `*-report-full.json` and `*-report-github.md` files into
   `tests/CredProx.Benchmarks/baselines/<new-version>/`.
3. Update `MACHINE.md` there with date, CPU/OS/.NET/job and the load averages
   before and after the pass.
4. Compare the previous release's baseline against the new run before overwriting
   history, so a regression is never baked into the new reference.

The 0.9.4 baseline lives in `baselines/0.9.4/`.

## A quieter machine (recommendation)

These numbers come from a general-purpose machine under ordinary load. For tighter
timing gates: a machine pinned to its performance CPU governor (or with
frequency scaling disabled), no desktop or container workloads during the pass, and
ideally isolated cores. On such a machine rerun the noise check (two unchanged
passes) and, if the ratio drift drops under ~3%, consider `TIMING_MODE=fail` for
all suites and a nightly schedule.

## Scrubbing allocation cost — M35 history

- The scrubber's buffers are pooled (M35): the scrub batch and the per-response
  pending buffer are rented from an `ArrayPool<byte>` seam and returned cleared,
  growth by rent-copy with a logical capacity so pool bucket sizes cannot change
  fill pacing. The OAuth cache-hit scrub arm dropped from 42,650 B to 9,729 B per
  request — against the same run's plain-YARP control arm (the pass-through floor;
  every ratio here uses that one control) 7.5× became 1.7×. Against the OAuth
  cache-hit control arm the scrubbed cost is 1.24× — the extra is the cache
  machinery, not the scrubber.
- SSE through CredProx dropped from 116,243 B to 81,129–88,747 B per connection
  across three independent runs (a 24–30% reduction). The SSE arms move up to
  about 9% run to run (their plain controls too), so read SSE figures as a range,
  not a point. The SSE payload carries no secret bytes —
  the arm measures the stream-scrubbing gate and the per-event machinery, not the
  redaction work itself, so it understates the cost of per-event redaction.
- Measured, then deliberately not changed: materializing header values in the
  response-header sweep (an enumerator-only rewrite measured a net +124 B per
  request — the header enumerators allocate as much as the copy they replace), and
  the synchronous `Read` bounce (the async YARP path never reaches it; the suites
  show zero allocation there).
- The SSE arm's remaining overhead over plain SSE (≈ +12–22 KB, run-dependent) sits
  in the response-scrubbing pipeline around the content/stream handoff — on this
  host EventPipe allocation sampling yields no events, so it is not attributable
  to a line without new instrumentation. Left as the committed cost of the current
  design, not a regression.
