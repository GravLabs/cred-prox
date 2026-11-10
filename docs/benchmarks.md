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

Results land in `BenchmarkDotNet.Artifacts/results/`: a GitHub-markdown report and a
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
| Overhead suite, allocations (SSE arms) | +3.3% / +5.6% |
| Micro suites, same-run ratio | ≤ ×1.13 (worst: the sub-microsecond destination arms — nanosecond-scale measurements against nanosecond-scale denominators) |
| Micro suites, absolute mean | ≤ +2.1% (except arms below ~100 ns, which track the ratio) |
| Micro suites, allocations | ≤ 16 B |

The SSE arms abandon a live stream mid-read, so the number of buffered socket
events per operation varies slightly with timing — their allocations are not fully
deterministic. Everything else on the list is.

## The gate: `scripts/bench-compare.sh`

```bash
scripts/bench-compare.sh tests/CredProx.Benchmarks/baselines/0.9.1 \
    tests/CredProx.Benchmarks/BenchmarkDotNet.Artifacts/results
```

Exits non-zero on a regression. Per method:

| Check | Overhead suite | Micro suites |
|---|---|---|
| Allocated bytes/op | FAIL above +32 B (SSE arms: +8%) | FAIL above +32 B |
| Same-run ratio rise | WARN above ×1.15 (noise reaches ×2.8 — a fail-gate there would be theatre) | WARN above ×1.15, **FAIL** above ×1.25 (worst observed unchanged drift ×1.13 — the warn threshold sits above it) |
| Absolute mean rise | WARN above ×1.15 | WARN above ×1.15 |

Overrides: `EPS_ALLOC`, `EPS_ALLOC_PCT`, `RATIO_WARN`, `RATIO_FAIL`, `MEAN_WARN`,
`ALLOW_PARTIAL=1` (accept a partial run, loudly), and `TIMING_MODE=fail|warn` to
force one mode for all suites — for example on a dedicated benchmarking machine,
where tightening the overhead timing gate becomes reasonable (see "A quieter
machine" below).

A method or suite present in the baseline but absent from the new run **FAILS** —
a lost or renamed arm is a regression, not a gap in the report. To gate a single
suite, either point both arguments at directories holding the same single suite's
baseline JSON (the gate then covers exactly that suite), or run against the full
baseline with `ALLOW_PARTIAL=1`, which downgrades the missing suites and methods to
loud warnings for a deliberate partial pass. A suite's baseline arm missing on
either side always FAILs: without its denominator the suite cannot gate timing.

Known blind spots: the same-run ratio is blind to a slowdown of the *baseline* arm
itself (plain YARP getting slower makes CredProx look better) — the absolute-mean
WARN catches most of that, and allocation checks are unaffected. And single-arm
suites (`AuditRedactorBenchmarks`) have no ratio gate at all: their only method is
their own baseline arm, so the ratio is 1.000→1.000 by construction and only the
allocation check and the never-failing absolute-mean WARN guard them.

A deliberate 8 KB per-request allocation on a hot arm and a 1 ms delay on a hot
micro method were each caught by the gate during development of the script
(sabotage probes, not committed behaviour).

## Refreshing the baseline at each release

1. Run a full pass on a quiet machine against the release commit (see above).
2. Copy the `*-report-full.json` and `*-report-github.md` files into
   `tests/CredProx.Benchmarks/baselines/<new-version>/`.
3. Update `MACHINE.md` there with date, CPU/OS/.NET/job and the load averages
   before and after the pass.
4. Compare the previous release's baseline against the new run before overwriting
   history, so a regression is never baked into the new reference.

The 0.9.1 baseline lives in `baselines/0.9.1/`.

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
