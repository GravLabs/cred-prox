#!/usr/bin/env bash
# Benchmark regression gate (plan §5.6): compares a BenchmarkDotNet results directory
# against a committed baseline directory and exits non-zero on a regression.
#
# Usage:  bench-compare.sh <baseline-dir> <new-results-dir>
#   Directories hold the *-report-full.json files written by tests/CredProx.Benchmarks
#   (BenchmarkDotNet.Artifacts/results after a run; baselines/0.9.1/ in the repo).
#
# Checks, per benchmark method that exists in both trees:
#   - Allocated bytes per operation: any increase beyond the arm's allowance FAILS.
#     Allocations on the deterministic arms proved stable to <0.1% across unchanged
#     reruns (docs/benchmarks.md), so a 32-byte absolute epsilon is generous for them.
#     Arms with MEASURED scheduling noise carry a proportional allowance instead —
#     a fraction of the BASELINE allocation, keyed by exact (suite, method) pair in
#     NOISY_ALLOC_FRACTION: the SSE arms at 8%, TokenCacheBenchmarks.SingleFlight at
#     max(32 B, 1%). The applied allowance is named on every gated arm's output line.
#     An arm joins the map only on measured noise with evidence in docs/benchmarks.md
#     — never to make a release pass.
#   - Same-run relative overhead: each suite's methods are divided by that suite's
#     baseline method WITHIN each run, and the ratio is compared across runs. A rise
#     above RATIO_WARN always warns; it FAILS only in fail-mode suites and only above
#     RATIO_FAIL. The mode split is from measured unchanged-rerun noise
#     (docs/benchmarks.md): the loopback-HTTP overhead suite drifts up to 2.8x so
#     timing there can only warn; the in-process suites gate, with RATIO_FAIL set
#     above their worst observed drift (sub-microsecond arms still drift ~13%).
#   - Absolute mean: a shift above MEAN_WARN warns everywhere — never fails.
#   - Coverage: a suite file or a benchmark method present in the baseline but absent
#     from the new run FAILS — a lost or renamed arm is exactly the regression this
#     gate exists to catch. ALLOW_PARTIAL=1 downgrades precisely those two cases to
#     loud warnings for deliberate partial runs. A suite's baseline arm missing (or
#     with a 0/null Mean) on either side FAILS unconditionally: without its
#     denominator the suite cannot gate timing at all.
#
# Environment overrides: EPS_ALLOC (bytes/op, flat arms), EPS_ALLOC_PCT (explicit ->
# re-fractions every NOISY_ALLOC_FRACTION arm; unset -> the per-arm fractions above;
# never touches flat arms), RATIO_WARN, RATIO_FAIL, MEAN_WARN (multipliers),
# TIMING_MODE (fail|warn) to
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
allow_partial = os.environ.get("ALLOW_PARTIAL") == "1"

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
    # socket events (measured +3.3%/+5.6% run to run).
    ("OverheadBenchmarks", "SsePlain"): 0.08,
    ("OverheadBenchmarks", "SseCredProx"): 0.08,
    # 64 concurrent waiters on a cold key: per-op allocation includes BCL
    # continuation objects that vary with inline-vs-scheduled completion.
    # Measured band 23,444-23,520 B at unchanged src (2026-11-11).
    ("TokenCacheBenchmarks", "SingleFlight"): 0.01,
}
# The single-flight allowance never dips below the flat epsilon:
# max(SINGLEFLIGHT_MIN_EPS, 1% of baseline).
SINGLEFLIGHT_MIN_EPS = 32.0
SINGLEFLIGHT_KEY = ("TokenCacheBenchmarks", "SingleFlight")

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
    for b in doc["Benchmarks"]:
        cls = b["Type"]
        m = b["MethodTitle"].split("(")[0]
        # An arm BDN reported "with issues" has Statistics/Memory null — keep loading
        # the file so the other arms still gate; the comparison flags these per method.
        stats = b.get("Statistics") or {}
        mem = b.get("Memory") or {}
        pct = stats.get("Percentiles") or {}
        out[(cls, m)] = {
            "mean": stats.get("Mean"),
            "alloc": mem.get("BytesAllocatedPerOperation"),
            "p95": pct.get("P95"),
        }
    return out

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
    base, new = load(base_file), load(new_file)
    print(f"== {name.removesuffix('-report-full.json')}")

    # A suite without its baseline arm (or with an unusable Mean there) cannot gate
    # timing at all — that FAILs unconditionally, partial mode or not.
    for cls in sorted({c for c, _ in base} | {c for c, _ in new}):
        bm = BASELINES.get(cls)
        if bm is None:
            continue
        kb = (cls, bm)
        missing_from = [s for s, run in (("baseline", base), ("new run", new)) if kb not in run]
        if missing_from:
            print(f"FAIL  {cls}: baseline arm {bm} missing from "
                  f"{' and '.join(missing_from)} — the suite cannot gate timing")
            fails += 1
        elif not base[kb]["mean"] or not new[kb]["mean"]:
            print(f"FAIL  {cls}: baseline arm {bm} has no usable Mean (0 or null)")
            fails += 1

    def ratio(run, key):
        cls, m = key
        base_m = BASELINES.get(cls)
        if base_m is None or (cls, base_m) not in run:
            return None
        num, den = run[key]["mean"], run[(cls, base_m)]["mean"]
        if not num or not den:
            return None
        return num / den

    for key in sorted(set(base) & set(new)):
        cls, m = key
        b, n = base[key], new[key]
        checked += 1
        if None in (b["mean"], b["alloc"], n["mean"], n["alloc"]):
            print(f"FAIL  {m}: no statistics (benchmark reported issues)")
            fails += 1
            continue
        problems = []  # (hard, text)

        # Applied allowance, shown on every gated arm. Default is the FLAT eps;
        # only an exact (suite, method) dict key (or an explicit EPS_ALLOC_PCT,
        # which re-fractions the dict arms — like the old SSE override) makes it
        # proportional, and the fraction always multiplies the BASELINE value.
        frac = NOISY_ALLOC_FRACTION.get(key)  # None for every flat arm
        if frac is not None and eps_pct_override is not None:
            frac = eps_pct_override  # the override re-fractions dict arms only
        if frac is None:
            method_eps = eps
            eps_note = f"allow +{method_eps:.0f} B flat"
        else:
            method_eps = b["alloc"] * frac
            eps_note = f"allow +{method_eps:.0f} B ({frac:.0%} of baseline)"
            if key == SINGLEFLIGHT_KEY:
                method_eps = max(SINGLEFLIGHT_MIN_EPS, method_eps)
                eps_note = (f"allow +{method_eps:.0f} B "
                            f"(max({SINGLEFLIGHT_MIN_EPS:.0f} B, {frac:.0%} of baseline))")
        if n["alloc"] > b["alloc"] + method_eps:
            problems.append((True,
                f"ALLOC {b['alloc']:.0f} B -> {n['alloc']:.0f} B "
                f"(+{n['alloc'] - b['alloc']:.0f} B exceeds {eps_note})"))

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
            print(f"FAIL  {m}: {seg}; " + "; ".join(t for _, t in problems))
            fails += 1
        elif problems:
            print(f"WARN  {m}: {seg}; " + "; ".join(t for _, t in problems))
            warns += 1
        elif rb is None or rn is None:
            print(f"RATIO-SKIPPED {m}: {seg}, "
                  f"mean {b['mean'] / 1e3:.2f}->{n['mean'] / 1e3:.2f} us "
                  f"(no usable baseline-arm ratio)")
        else:
            print(f"ok    {m}: {seg}, "
                  f"mean {b['mean'] / 1e3:.2f}->{n['mean'] / 1e3:.2f} us "
                  f"ratio {rb:.3f}->{rn:.3f}")

    missing = set(base) - set(new)
    for cls, m in sorted(missing):
        if allow_partial:
            print(f"WARN  {m}: present in baseline, absent in new run "
                  f"(ALLOW_PARTIAL=1 — method NOT gated)")
            warns += 1
        else:
            print(f"FAIL  {m}: present in baseline, absent in new run")
            fails += 1

print(f"\nbench-compare: {checked} methods compared, FAIL={fails} WARN={warns}"
      + ("  [ALLOW_PARTIAL=1 — partial run, coverage reduced]" if allow_partial else ""))
sys.exit(1 if fails else 0)
PY
