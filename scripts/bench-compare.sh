#!/usr/bin/env bash
# Benchmark regression gate (plan §5.6): compares a BenchmarkDotNet results directory
# against a committed baseline directory and exits non-zero on a regression.
#
# Usage:  bench-compare.sh <baseline-dir> <new-results-dir>
#   Directories hold the *-report-full.json files written by tests/CredProx.Benchmarks
#   (BenchmarkDotNet.Artifacts/results after a run; baselines/0.9.3/ in the repo).
#
# Checks, per benchmark method that exists in both trees:
#   - Allocated bytes per operation: any increase beyond the arm's allowance FAILS.
#     Allocations on the deterministic arms proved stable to <0.1% across unchanged
#     reruns (docs/benchmarks.md), so a 32-byte absolute epsilon is generous for them.
#     Arms with MEASURED scheduling noise carry a proportional allowance instead —
#     a fraction of the BASELINE allocation, keyed by exact (suite, method) pair in
#     NOISY_ALLOC_FRACTION: the SSE arms at 12%, TokenCacheBenchmarks.SingleFlight
#     at max(32 B, 1%). The applied allowance is named on every gated arm's output line.
#     An arm joins the map only on measured noise with evidence in docs/benchmarks.md
#     — never to make a release pass.
#     The two SSE arms are WARN-only above their fraction, keyed by exact
#     (suite, method) pair in GROSS_ALLOC_FAIL_MULT: an interleaved A/B attribution
#     (2026-11-15) showed the released 0.9.4 code exceeds its own 12% allowance in
#     2 of 3 quiet-gated passes — the same rate as the candidate, with no changed
#     code in the arm's path — so the fraction cannot gate them as a FAIL. They
#     still hard-FAIL above 2.5x the BASELINE allocation: the gross-regression trip
#     line (buffering the stream, a scrub blow-up). Every other arm is unchanged.
#   - Same-run relative overhead: each suite's methods are divided by that suite's
#     baseline method WITHIN each run, and the ratio is compared across runs. A rise
#     above RATIO_WARN always warns; it FAILS only in fail-mode suites and only above
#     RATIO_FAIL. The mode split is from measured unchanged-rerun noise
#     (docs/benchmarks.md): the loopback-HTTP overhead suite drifts up to 2.8x so
#     timing there can only warn; the in-process suites gate, with RATIO_FAIL set
#     above their worst observed drift (sub-microsecond arms still drift ~13%).
#   - Absolute mean: a shift above MEAN_WARN warns everywhere — never fails.
#   - Statistics depth: a new-run arm with Statistics.N below N_FLOOR (10) WARNs —
#     a thin sample cannot support any of the statistics the gate reads. The arm's
#     N and P95 (from Statistics.Percentiles) print on every ok line so a quiet
#     pass still shows what the verdict rested on.
#   - Coverage: a suite file or a benchmark method present in the baseline but absent
#     from the new run FAILS — a lost or renamed arm is exactly the regression this
#     gate exists to catch. ALLOW_PARTIAL=1 downgrades precisely those two cases to
#     loud warnings for deliberate partial runs. A suite's baseline arm missing (or
#     with a 0/null Mean) on either side FAILS unconditionally: without its
#     denominator the suite cannot gate timing at all. With ALLOW_PARTIAL=1, a run
#     that compares ZERO methods FAILS — partial still has to mean some coverage.
#   - Comparison key: (suite class, method, Parameters). Including Parameters keeps
#     [Params]/[Arguments] rows distinct instead of silently collapsing them into one
#     arm; two rows identical in title AND parameters FAIL as a duplicate.
#   - A RATIO-SKIPPED arm (its suite's baseline arm missing or unusable, so the
#     timing gate did not run) counts as WARN in warn-mode suites and FAIL in
#     fail-mode ones — the summary never reads clean while a gate sat out.
#   - RATIO_WARN must be below RATIO_FAIL or the timing FAIL is unreachable: the
#     script refuses to start (exit 2) on inverted thresholds.
#
# Environment overrides: EPS_ALLOC (bytes/op, flat arms), EPS_ALLOC_PCT (explicit ->
# re-fractions every NOISY_ALLOC_FRACTION arm; unset -> the per-arm fractions above;
# never touches flat arms), RATIO_WARN, RATIO_FAIL, MEAN_WARN (multipliers),
# N_FLOOR (statistics-count warn floor, default 10), TIMING_MODE (fail|warn) to
# force every suite into one mode — for example on a dedicated quiet machine — and
# ALLOW_PARTIAL=1 to accept a partial run (gates only what is present, loudly).
set -u

BASE_DIR="${1:-}"
NEW_DIR="${2:-}"
if [ -z "$BASE_DIR" ] || [ -z "$NEW_DIR" ]; then
    echo "usage: bench-compare.sh <baseline-dir> <new-results-dir>" >&2
    exit 2
fi
compgen -G "$BASE_DIR/*-report-full.json" > /dev/null || {
    echo "ERROR: no baseline JSON in $BASE_DIR" >&2
    exit 2
}

EPS_ALLOC="${EPS_ALLOC:-32}" EPS_ALLOC_PCT_RAW="${EPS_ALLOC_PCT:-}" \
RATIO_WARN="${RATIO_WARN:-1.15}" RATIO_FAIL="${RATIO_FAIL:-1.25}" \
TIMING_MODE="${TIMING_MODE:-auto}" MEAN_WARN="${MEAN_WARN:-1.15}" \
N_FLOOR="${N_FLOOR:-10}" \
ALLOW_PARTIAL="${ALLOW_PARTIAL:-0}" \
python3 - "$BASE_DIR" "$NEW_DIR" <<'PY'
import glob, json, os, sys

base_dir, new_dir = sys.argv[1], sys.argv[2]
eps = float(os.environ["EPS_ALLOC"])
_raw_pct = os.environ.get("EPS_ALLOC_PCT_RAW", "")
# An EXPLICIT EPS_ALLOC_PCT re-fractions the dict arms (the old SSE override, widened
# to cover every dict arm); it never touches flat arms. Unset -> per-arm fractions.
eps_pct_override = float(_raw_pct) if _raw_pct else None
ratio_warn = float(os.environ["RATIO_WARN"])
ratio_fail = float(os.environ["RATIO_FAIL"])
timing_mode = os.environ["TIMING_MODE"]
mean_warn = float(os.environ["MEAN_WARN"])
n_floor = int(os.environ["N_FLOOR"])
allow_partial = os.environ.get("ALLOW_PARTIAL") == "1"

# Inverted thresholds make the timing FAIL unreachable (warn fires first, the fail
# test is strictly above it) — refuse to start instead of reporting a gate that
# cannot bite.
if ratio_warn >= ratio_fail:
    print(f"ERROR: RATIO_WARN ({ratio_warn}) must stay below RATIO_FAIL ({ratio_fail})"
          " — the timing FAIL would be unreachable", file=sys.stderr)
    sys.exit(2)

# Timing policy per suite, from measured unchanged-rerun noise (docs/benchmarks.md):
# the loopback-HTTP overhead suite's same-run ratio drifts by factors of 1.6-2.8 on a
# shared machine, so timing there can only warn; the in-process suites are stable
# enough to fail on. TIMING_MODE=fail|warn overrides for all suites.
TIMING_BY_SUITE = {"OverheadBenchmarks": "warn"}

# Methods whose per-op allocation is timing-dependent, with the allowance FRACTION
# applied to the BASELINE value (never the new run's). Keys are exact (suite, method)
# pairs — never substring or suite-level matches. An arm qualifies only on measured
# scheduling noise with evidence in docs/benchmarks.md ("Measured noise"), never to
# make a release pass. Every other arm keeps the flat EPS_ALLOC — the dict default
# is the flat epsilon, never the proportional one.
NOISY_ALLOC_FRACTION = {
    # A stream abandoned mid-read leaves a run-dependent number of buffered
    # socket events. After the M37 3-event cap the SSE allocations are ~8x
    # smaller than the old ~5 s abandoned stream, so that count is a larger
    # SHARE of them: across 6 pinned passes at unchanged workload (the reference
    # pass + 5, 2026-11-14) the max UPWARD excursion over the reference is
    # +1,520 B = 10.5% (SseCredProx 15,989 vs ref 14,469; SsePlain never rose
    # above its reference). 12% covers that with a modest margin and misses at
    # most a +1,736 B regression (docs/benchmarks.md).
    ("OverheadBenchmarks", "SsePlain"): 0.12,
    ("OverheadBenchmarks", "SseCredProx"): 0.12,
    # 64 concurrent waiters on a cold key: per-op allocation includes BCL
    # continuation objects that vary with inline-vs-scheduled completion.
    # Measured band 23,444-23,520 B at unchanged src (2026-11-11).
    ("TokenCacheBenchmarks", "SingleFlight"): 0.01,
}
# The single-flight allowance never dips below the flat epsilon:
# max(SINGLEFLIGHT_MIN_EPS, 1% of baseline).
SINGLEFLIGHT_MIN_EPS = 32.0
SINGLEFLIGHT_KEY = ("TokenCacheBenchmarks", "SingleFlight")

# Arms whose allocation excursion above their NOISY_ALLOC_FRACTION WARNs instead of
# FAILing, with the multiplier on the BASELINE allocation that still hard-FAILs.
# Keyed by exact (suite, method) pair — same discipline as the fraction table,
# never a suite-name match. 2.5x sits above the measured scheduling tail (across
# nine quiet-gated passes 2026-11-15 the worst value was 1.95x of the 13,117 B
# reference — and the released-code control alone reached 1.26x — while both trees
# failed the 12% line at the same rate) and below gross regressions like buffering
# the stream or a scrub blow-up. docs/benchmarks.md carries the evidence.
GROSS_ALLOC_FAIL_MULT = {
    ("OverheadBenchmarks", "SsePlain"): 2.5,
    ("OverheadBenchmarks", "SseCredProx"): 2.5,
}

def suite_timing(suite):
    return timing_mode if timing_mode in ("fail", "warn") else TIMING_BY_SUITE.get(suite, "fail")

# Each suite's baseline method: the [Benchmark(Baseline = true)] method whose per-run
# mean is the denominator for the same-run ratio.
BASELINES = {
    "OverheadBenchmarks": "PlainYarp",
    "DestinationBenchmarks": "Lookup",
    "PresetBenchmarks": "NoPresets",
    "TokenCacheBenchmarks": "CacheHit",
    "AuditRedactorBenchmarks": "Redact",
}

def load(path):
    with open(path) as f:
        doc = json.load(f)
    out = {}
    dupes = []
    for b in doc["Benchmarks"]:
        cls = b["Type"]
        m = b["MethodTitle"].split("(")[0]
        # Parameters belongs in the key: [Params]/[Arguments] rows share a MethodTitle,
        # and dropping the parameters collapses two arms into one (same failure family
        # as a dropped arm). A row identical in title AND parameters is a true duplicate.
        params = b.get("Parameters") or ""
        # An arm BDN reported "with issues" has Statistics/Memory null — keep loading
        # the file so the other arms still gate; the comparison flags these per method.
        stats = b.get("Statistics") or {}
        mem = b.get("Memory") or {}
        pct = stats.get("Percentiles") or {}
        key = (cls, m, params)
        if key in out:
            dupes.append(key)
        out[key] = {
            "mean": stats.get("Mean"),
            "alloc": mem.get("BytesAllocatedPerOperation"),
            "p95": pct.get("P95"),
            "n": stats.get("N"),
        }
    return out, dupes

def label(m, params):
    return m if not params else f"{m}({params})"

fails = warns = checked = 0
if allow_partial:
    print("!! ALLOW_PARTIAL=1: deliberate PARTIAL run — a suite file or a non-baseline\n"
          "!! method missing from the new run WARNs instead of FAILing (coverage is\n"
          "!! reduced to what is present). A missing or zero baseline arm still FAILs.")
for base_file in sorted(glob.glob(os.path.join(base_dir, "*-report-full.json"))):
    name = os.path.basename(base_file)
    new_file = os.path.join(new_dir, name)
    if not os.path.exists(new_file):
        if allow_partial:
            print(f"WARN  {name}: missing in new results (ALLOW_PARTIAL=1 — suite NOT gated)")
            warns += 1
        else:
            print(f"FAIL  {name}: missing in new results")
            fails += 1
        continue
    base, dup_b = load(base_file)
    new, dup_n = load(new_file)
    print(f"== {name.removesuffix('-report-full.json')}")
    # Duplicate (class, method, parameters) rows make the comparison key ambiguous;
    # which row wins depends on JSON order. Never gate an ambiguous file — and never
    # partial-downgrade this: the file itself is malformed.
    for src, dups in (("baseline", dup_b), ("new run", dup_n)):
        for cls, m, params in dups:
            print(f"FAIL  {cls}.{label(m, params)}: duplicate row in {src} report")
            fails += 1

    # A suite without its baseline arm (or with an unusable Mean there) cannot gate
    # timing at all — that FAILs unconditionally, partial mode or not.
    for cls in sorted({c for c, _, _ in base} | {c for c, _, _ in new}):
        bm = BASELINES.get(cls)
        if bm is None:
            continue
        # One check per parameter set in play: each [Params] row of the suite needs
        # its own same-parameters baseline arm as the denominator. (With no
        # [Params] benchmarks — every suite today — this is exactly one pass.)
        for params in sorted({p for c, _, p in base if c == cls}
                             | {p for c, _, p in new if c == cls}):
            kb = (cls, bm, params)
            missing_from = [s for s, run in (("baseline", base), ("new run", new)) if kb not in run]
            if missing_from:
                print(f"FAIL  {cls}: baseline arm {label(bm, params)} missing from "
                      f"{' and '.join(missing_from)} — the suite cannot gate timing")
                fails += 1
            elif not base[kb]["mean"] or not new[kb]["mean"]:
                print(f"FAIL  {cls}: baseline arm {label(bm, params)} has no usable Mean (0 or null)")
                fails += 1

    def ratio(run, key):
        cls, m, params = key
        base_m = BASELINES.get(cls)
        den_key = (cls, base_m, params) if base_m is not None else None
        if den_key is None or den_key not in run:
            return None
        num, den = run[key]["mean"], run[den_key]["mean"]
        if not num or not den:
            return None
        return num / den

    for key in sorted(set(base) & set(new)):
        cls, m, params = key
        m_label = label(m, params)
        b, n = base[key], new[key]
        checked += 1
        if None in (b["mean"], b["alloc"], n["mean"], n["alloc"]):
            print(f"FAIL  {m_label}: no statistics (benchmark reported issues)")
            fails += 1
            continue
        problems = []  # (hard, text)

        # Applied allowance, shown on every gated arm. Default is the FLAT eps;
        # only an exact (suite, method) dict key (or an explicit EPS_ALLOC_PCT,
        # which re-fractions the dict arms — like the old SSE override) makes it
        # proportional, and the fraction always multiplies the BASELINE value.
        # The allowance dict is keyed (suite, method) while the COMPARISON key
        # carries Parameters — look the allowance up by the 2-tuple or no dict
        # arm ever matches (M37 fold F1: the 3-tuple lookup silently flat-32'd
        # every arm, killing the 0.9.3 owner-ruled per-arm allowance).
        sm_key = (cls, m)
        frac = NOISY_ALLOC_FRACTION.get(sm_key)  # None for every flat arm
        if frac is not None and eps_pct_override is not None:
            frac = eps_pct_override  # the override re-fractions dict arms only
        gross_mult = GROSS_ALLOC_FAIL_MULT.get(sm_key)  # None for every hard arm
        if frac is None:
            method_eps = eps
            eps_note = f"allow +{method_eps:.0f} B flat"
        else:
            method_eps = b["alloc"] * frac
            eps_note = (f"allow +{method_eps:.0f} B ({frac:.0%} of baseline)"
                        + ("" if gross_mult is None else f" warn, fail above {gross_mult}x"))
            if sm_key == SINGLEFLIGHT_KEY:
                method_eps = max(SINGLEFLIGHT_MIN_EPS, method_eps)
                eps_note = (f"allow +{method_eps:.0f} B "
                            f"(max({SINGLEFLIGHT_MIN_EPS:.0f} B, {frac:.0%} of baseline))")
        if n["alloc"] > b["alloc"] + method_eps:
            if gross_mult is not None and n["alloc"] > b["alloc"] * gross_mult:
                problems.append((True,
                    f"ALLOC {b['alloc']:.0f} B -> {n['alloc']:.0f} B "
                    f"(x{n['alloc'] / b['alloc']:.2f} of baseline exceeds gross-fail {gross_mult}x)"))
            else:
                problems.append((gross_mult is None,
                    f"ALLOC {b['alloc']:.0f} B -> {n['alloc']:.0f} B "
                    f"(+{n['alloc'] - b['alloc']:.0f} B exceeds {eps_note})"))

        # Thin statistics understate every check below (means, ratios, percentiles).
        # The committed baseline passed review once; the floor gates the NEW run.
        if n["n"] is not None and n["n"] < n_floor:
            problems.append((False, f"N={n['n']} below statistics floor {n_floor}"))

        rb, rn = ratio(base, key), ratio(new, key)
        mode = suite_timing(cls)
        if rb and rn and rb > 0:
            rise = rn / rb
            if rise > ratio_warn:
                hard_ratio = mode == "fail" and rise > ratio_fail
                problems.append((hard_ratio,
                    f"{'RATIO' if hard_ratio else 'ratio'} {rb:.3f} -> {rn:.3f} "
                    f"(x{rise:.2f}; fail-above {ratio_fail} in {mode}-mode)"))

        if b["mean"] > 0 and n["mean"] / b["mean"] > mean_warn:
            problems.append((False,
                f"MEAN {b['mean'] / 1e3:.2f} us -> {n['mean'] / 1e3:.2f} us (x{n['mean'] / b['mean']:.2f})"))

        # Every gated arm's line names the allowance that was applied to it.
        seg = f"alloc {b['alloc']:.0f}->{n['alloc']:.0f} B [{eps_note}]"
        if any(h for h, _ in problems):
            print(f"FAIL  {m_label}: {seg}; " + "; ".join(t for _, t in problems))
            fails += 1
        elif problems:
            print(f"WARN  {m_label}: {seg}; " + "; ".join(t for _, t in problems))
            warns += 1
        elif rb is None or rn is None:
            # A timing gate that did not run is a gap, not a pass: count it, so the
            # summary line can never read clean while a gate sat out. Hard in
            # fail-mode suites, warn-only where timing can only warn anyway.
            if mode == "fail":
                print(f"RATIO-SKIPPED {m_label}: {seg}, "
                      f"mean {b['mean'] / 1e3:.2f}->{n['mean'] / 1e3:.2f} us "
                      f"(no usable baseline-arm ratio — FAIL in fail-mode)")
                fails += 1
            else:
                print(f"RATIO-SKIPPED {m_label}: {seg}, "
                      f"mean {b['mean'] / 1e3:.2f}->{n['mean'] / 1e3:.2f} us "
                      f"(no usable baseline-arm ratio — counted as WARN)")
                warns += 1
        else:
            def p95_us(v):
                return "n/a" if v is None else f"{v / 1e3:.2f}"
            print(f"ok    {m_label}: {seg}, "
                  f"mean {b['mean'] / 1e3:.2f}->{n['mean'] / 1e3:.2f} us "
                  f"ratio {rb:.3f}->{rn:.3f}, "
                  f"N={n['n']} p95 {p95_us(b['p95'])}->{p95_us(n['p95'])} us")

    missing = set(base) - set(new)
    for cls, m, params in sorted(missing):
        if allow_partial:
            print(f"WARN  {label(m, params)}: present in baseline, absent in new run "
                  f"(ALLOW_PARTIAL=1 — method NOT gated)")
            warns += 1
        else:
            print(f"FAIL  {label(m, params)}: present in baseline, absent in new run")
            fails += 1

# ALLOW_PARTIAL forgives missing suites and methods — but zero methods compared
# means nothing was gated at all, which is not "partial", it is empty.
if allow_partial and checked == 0:
    print("FAIL  ALLOW_PARTIAL=1 but ZERO methods compared — nothing was gated")
    fails += 1

print(f"\nbench-compare: {checked} methods compared, FAIL={fails} WARN={warns}"
      + ("  [ALLOW_PARTIAL=1 — partial run, coverage reduced]" if allow_partial else ""))
sys.exit(1 if fails else 0)
PY
