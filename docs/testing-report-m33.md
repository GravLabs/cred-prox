# M33 testing report — soak + failure injection

Run: `tools/m33-soak` on branch `m33-soak-fault` (harness at d664f8b; the fault-7 fix is
0fcfe96), plan §5.5 is the design of record and the authority for every pre-stated expectation
quoted below. All figures in the results tables come from the run directory artifacts
(`stats.csv`, `faults/k6-summary-*.json`, `faults/host-*.log`, `secret-scan-hits.txt`);
nothing here is estimated.

**Status: COMPLETE — the one product deviation is fixed (§5 entry 4, commit 0fcfe96 with full
gates), and the three shallow-witness faults were re-exercised by B3 (§5 entry 3; §4 rows 2/3/6
now PASS on live evidence).** Attempt #2 (2026-11-09 01:03–07:07Z): steady soak PASSED and
faults 1a/1b/4/5/8 completed clean (their run dir `m33-soak-20261109-010309` stays the evidence
of record); the four WireMock-scenario faults (2/3/6/7) had silently no-op'd — harness bug (§5,
entry 2) — and were re-run by `scripts/phase-b2.sh` in run dir `m33-soak-20261109-075813`
(07:58–08:47Z, `PHASE-B2-DONE`, `FINAL-SCAN-ZERO`, teardown clean), reusing the steady baseline.
The B2 re-run executed all four swaps for real (journal-verified) and produced **one product
finding (fault 7 clock skew)** plus three harness levers that proved too shallow to exercise
their target behaviour; B3 (dir `m33-soak-20261109-101912`, 10:19–10:49Z) closed those three
with the opt-in features wired and the rotate lever deepened. Attempt #1 was invalidated
mid-run by a harness fault (§5, entry 1).

## 1. Environment

| Item | Value |
|---|---|
| Proxy under test | published CredProx **0.9.0** package (host-publish, pinned aspnet runtime image) |
| Topology | soakhost 2.0c/1536m · wiremock 1.5c/1024m · toxiproxy 0.5c/256m · k6 2.0c/1024m — Σ caps 6.0 CPU / 3.75 GiB (§5.5 table) |
| Load | k6 constant-arrival-rate scenarios: cc 40 rps, gen1 25 rps, login 2 rps, SSE 2 rps |
| Faults | Toxiproxy toxics + WireMock stub-swap overrides via `scripts/faults.sh` (levers print each expectation and `swap-on/swap-off` markers the driver asserts) |
| Budget guard | hourly `uptime`; 5-min load > 40 → BACKOFF (kill k6, teardown). Observed max: the six hourly readings all truncated to 0 whole load units (int read of a sub-2 5-min average); no BACKOFF |

## 2. Smoke (pre-flight gate)

Smoke #9, 2026-11-08 21:47Z: 12 422 requests, 100% checks pass, error rate 0, scrub witness 0,
secret-scan zero hits, 0 host exceptions, teardown clean (`/tmp/m33-smoke9.log`, run dir
`m33-soak-20261108-214724`). Nine smoke iterations were needed; all six defects found were
**harness bugs** (KV stub trailing-slash 404, stub readiness race + transport retry poison,
Toxiproxy config shape + localhost API bind, three k6-1.x breakers, unwritable summary path) —
no library findings; details in commit 199c3c7. Smoke also earned a runner change: the DONE marker
now requires the functional load gate (error rate ≤ 1%, scrub sum = 0) because smoke #5 showed a
DONE marker can coexist with 100% dead traffic.

## 3. Steady soak (270 min, warm-up included)

Pass bands (§5.5): RSS slope ≤ +5 MB/h over the last 2 h; sockets/threads within ±10% of the
warm-up band; error drift ≤ 0.1 pp; p99 ≤ 2× the warm-up median.

Mid-run protection during the steady soak: a 60-s container-liveness watchdog (any infra
container leaving `running` stops k6 and fails the run at once) plus a k6 cumulative
error-rate threshold (5% with `abortOnFail`) as backstop. **Stated limit of the backstop**
(design note 2026-11-09 01:04Z): the threshold is cumulative, so late in a clean run it
dilutes — after ~4 h clean it needs ~12 min of 100% failure to cross 5%; a broken-but-alive
upstream is therefore caught by the watchdog (containers) or by the end-of-window gate
(rates), not quickly by the threshold.

Collector bands from `stats.csv` (540 steady rows @30 s; warm-up = first 60 rows, final = last
60; RSS slope = linear fit over the last 240 rows; columns per `SoakHost/Program.cs:114-123`):

| Metric | Warm-up (0-30 min) | Final (last 30 min) | Verdict |
|---|---|---|---|
| RSS slope (last 2 h) | — | −0.62 MiB/h (flat-decreasing; peak 129.7 MiB) | **PASS** (band ≤ +5 MB/h) |
| RSS level | 122.6 MiB | 124.7 MiB | **PASS** |
| GC heap total (MiB) — the §5.5 ±10 % band quantity | 10.7 | 9.7 | **PASS** (−9.5 % vs warm-up, inside ±10 %; trend is down). The gen2 sub-pool alone rose 860 → 1 753 KiB sawtoothing below 2 MB — the collector's own band is on the total, so gen2 growth inside a flat-to-decreasing heap is not itself a band breach |
| Threads | 19.5 | 19.0 (steady range 19-20) | **PASS** (±10 %) |
| TCP established | 27.9 | 28.4 (steady range 28-35) | **PASS** (+1.8 %) |
| http_req_failed (k6) | 0.0000 | 0.0000 (run aggregate) | **PASS** (drift 0) |
| p50 / p95 / p99 | 5.33 / 18.5 / 205.6 ms | run-aggregate only — see limit below | **"p99 ≤ 2× first hour" band NOT MEASURED** (aggregate-only line file, limit below); p99 floor = SSE stub 200 ms delay |
| scrub witness (k6 caller-side) | 0 | 0 | **PASS** |

Honest limit: the k6 line file keeps only the final run-aggregate row (the container rewrites
it each run), so warm-up-vs-final latency/error splits are not available for the steady soak —
the collector bands above carry the drift judgement, and the per-window splits exist for the
fault windows (§4).

## 4. Fault sequence — each judged against the §5.5 expectation fixed BEFORE the run

Window/recovery k6 rates from `faults/k6-summary-*.json`, wire witnesses from
`journal/journal-*-*.json.gz` (post-reset, so window-complete), host slices from
`faults/host-*.log`. Clean-window baseline: /idp/token 10 mints per 5-min window (3 keys,
cache-expiry-driven), p95 ≈ 6.4 ms. Runs: rows 1a/1b/4/5/8 from attempt #2 (dir
`m33-soak-20261109-010309`); row 7 from B2 (dir `m33-soak-20261109-075813`); rows 2/3/6 from
**B3** (dir `m33-soak-20261109-101912`, opt-in features wired, rotate lever deepened — §5 entry 3;
"dir 101912" below).

| # | Fault | Pre-stated expectation (§5.5) | Observed | Verdict |
|---|---|---|---|---|
| 1a | IdP slow (latency 900±100 ms) | single-flight: one `/idp/token` per key per window despite N waiters; documented 502 shape on exhaustion | journal: 10 `/idp/token` mints — identical to the clean-window baseline despite 900 ms mint latency behind 67 rps of cache-miss pressure; zero exhaustion needed (never left documented shape); window failed 0.0000, checks 1.000, p95 6.8 ms | **PASS** |
| 1b | IdP down (reset_peer) | callers get `credential_unavailable` 502; recovery ≤ 2 token requests per key (no herd) | window failed 0.584 with the documented shape — 12 162 `CredentialAttachFeature` warns "Not Proxying, a response was set by the transforms"; recovery window mints = 10 = baseline exactly (no herd); recovery failed 0.0034 transient → 0 | **PASS** |
| 2 | Vendor 429 + `Retry-After: 5` | cluster pauses ≈ Retry-After (±1 s) then lifts; nothing silently retried in the journal | **B3 run (dir 101912, `AddCredProxThrottling` wired):** only 693 vendor 429s (346 cc + 347 gen1) reached the vendor, in 61 bursts spaced **5.00–5.03 s** apart (median gap 5.00 s = Retry-After to the hundredth) — the cluster pauses on each vendor 429 and lifts exactly on the advertised interval; caller-side latency shows the pause mass: window med 4 800 ms, p99 5 009 ms, max 5 221 ms (queueing to `MaxQueueWait` 5 s then shedding); the 693 pass-throughs are one journal hit each with `Retry-After: 5` unchanged (no silent retries; the remaining ~19.8k callers got `credprox.throttled` 429s with no vendor hit); recovery: 20 472 requests at baseline volumes, vendor-side journal 100 % 200, k6 failed 0.0013 — ~27 shed 429s while the pause drained after swap-off, zero non-200 on the wire | **PASS** (pause ±0.03 s of Retry-After; lifts; no silent retries; B2's inert-feature finding superseded — §5 entry 3) |
| 3 | Vendor 5xx burst | breaker opens at configured ratio → 503; half-open probes exactly at count; closes after successes | **B3 run (dir 101912, `AddCredProxResilience` wired, config rekeyed to the live `vendor` cluster):** 293 vendor 500s (176 cc + 117 gen1) against ~20.4k callers — the breaker opened at the configured 0.5/4 posture and held; every other caller got the sub-millisecond `credprox.upstream_unavailable` 503 shape (window med 0.3 ms, p99 1.3 ms, failed 0.9997); half-open: one probe per cluster per **5.00–5.03 s** break, 60 consecutive break cycles, every probe journal-confirmed (stub live all window); recovery: first successful probe closed it — vendor-side journal 20 481 requests 100 % 200, k6 failed 0.0128 concentrated in the seconds before that first success, back to p95 6.6 ms | **PASS** (opens at ratio; probes at the break interval; closes on first success; B2's inert-feature finding superseded — §5 entry 3) |
| 4 | Vendor timeout (reset mid-response/SSE) | clean failures within attempt timeout, no hang; sockets to baseline ≤ 60 s; SSE terminates, not stalls | 100 % failures as designed, clean at the attempt timeout (med 1.01 s, p95 1.81 s), windows ended on schedule (no hang); 7 028 handled YARP warns, 0 crit/unhandled lines; `stats.csv` tcp at the clear instant: 28→28→28→28 (baseline, first sampled row ≤ 30 s); recovery failed 0.0000 | **PASS** |
| 5 | Config reload under load (secret+generation swapped atomically; allow-list edit) | journal pairs (gen tag, matching secret) only — zero mixed pairs; failed rebind keeps serving | atomic swap landed mid-window (`REBOUND gen1 secret + caller-b allow-list`): zero failed requests across the rebind (0.0000), checks 1.000 throughout; journal marker↔route↔auth-echo pairs consistent at baseline volumes (12 001 cc / 8 102 gen1), no 403/401 leakage between callers; limit: bearer tokens are opaque, so pairing is witnessed route↔marker↔status, not token-content↔secret | **PASS** |
| 6 | KV rotation via the REAL provider (1.3.x `AddAzureKeyVault` + `ReloadInterval` 10 s, transport-swap to loopback stub; design decision 2026-11-08) | next-mint semantics: minted tokens work to expiry; new mints pick rotated value ≤ 2 provider ticks; no 401 storm; exactly one reload per flip | **B3 run (dir 101912, rotate lever now swaps `kv_list` with a bumped `attributes.updated` too):** exactly one per-secret GET per flip — window: 1 GET +2 s after the swap serving `KV-GEN2-ROTATED` (`updated: 1730009999`), recovery: 1 GET +2 s after clear serving the original value (`updated` back); list polls stay flat at 30/window (no polling storm); both windows k6 failed 0.0000, checks 1.0000 (minted tokens served to expiry, no 401-class errors). Stated limit: the battery's k6 scenarios never drive route `gen2`, so the attach-layer walk (rotated value on outbound vendor calls) is not exercised by battery traffic — it was sabotage-probed on this exact build pre-launch, journal-witnessed on `X-Vendor-Key` kv1→rotated→kv1 within one tick — §5 entry 3 | **PASS** (reload semantics live; attach-walk probe-witnessed with the gen2-traffic limit stated) |
| 7 | Clock skew (`expires_in: -30` stub IdP) | near/past-expiry tokens refresh; zero vendor 401s from expiry; refresh stays single-flight | **DEVIATION vs expectation.** With the skew stub live: exactly **1** `/idp/token` mint for the whole 5-min window (negative `expires_in` body journal-confirmed) and **0** in recovery, against the 10/window baseline — refresh stopped rather than fired. Product code explains it: `ReadLifetime` treats a non-positive `expires_in` as absent and falls back to `DefaultLifetime` = 1 h (`src/CredProx/Credentials/OAuthClientCredentialsProvider.cs:180-182`), so the past-expiry token is cached and served for up to an hour — against a real vendor, a 1-hour window of expired-token traffic. Zero-401 clause held but is weak evidence here: the stub vendor echoes without validating expiry. Single-flight: trivially held (1 mint, no herd). Classified **library-behaviour deviation** — fixed in commit 0fcfe96: a negative `expires_in` is now rejected through the `credential_unavailable` path with nothing cached, and regression tests pin the behaviour against the live provider path (full §5.3 gates; §5 entry 4). Not re-run in the soak battery (B3 covered faults 2/3/6 per the design decision); the fix's runtime shape is unit- and integration-tested, not soak-re-run | **FAIL (B2 run) → FIXED in 0fcfe96** (§5 entry 4) |
| 8 | Slowloris (≤ 64 sockets, drip) under load | normal p95 ≤ +20%; refusals from Kestrel limits, threads in band; baseline returns when clients drop | normal-traffic p95 6.5 ms vs 6.4 ms baseline (+2 %); drip held 64 sockets for 120 s (`slowloris.log`) while `stats.csv` tcp peaked 92 vs 28 baseline — extra sockets accepted, threads max 22 (in band, no exhaustion); recovery p95 6.4 ms. **Refusal clause NOT EXERCISED:** all 64 abusive sockets were accepted — the Kestrel connection limit was never reached, so "refusals from Kestrel limits" has no witness either way; the row is judged on the measured clauses only | **PASS** on measured clauses; refusal clause NOT EXERCISED |

Secret hygiene: `secret-scan` after every fault + final, zero hits required — every executed
fault (1a, 1b, 4, 5, 8 in attempt #2; 2, 3, 6, 7 in B2) printed `SCAN-ZERO`, the final scan is
`FINAL-SCAN-ZERO`, and `secret-scan-hits.txt` is 0 bytes in both run dirs. The scan covers the
product's own outputs (host logs, k6 caller-side files, stats, fault slices); the WireMock
journal is the vendor-side wire witness and legitimately carries raw stub values on the wire
(M20 scrubbed-echo doctrine; caller-side witness is the k6 body check).

## 5. Deviations and triage

- **Harness incident (invalidated attempt #1; no product deviation).** Run
  `m33-soak-20261108-215247`: WireMock's unbounded request journal hit the 1 GiB container
  cap and was OOMKilled (exit 137) at 23:42:44Z, ~1h50m in; the runner did not abort —
  the error gate evaluated only at window end and the watchdog checked load only — so k6
  drove the dead upstream for 45 more min. The run is INVALID from that timestamp. CredProx
  itself was unaffected (73 MiB RSS, 0 exceptions at 2h33m). Fixed in 28d4a3a: journal ring
  capped at 30k entries (`-Xmx512m`), per-fault-window journal reset + gzipped capture, 60-s
  infra-liveness watchdog with loud abort, k6 steady-window cumulative error-rate abort
  (backstop; limit stated in §3). Sabotage-probed before relaunch: killing WireMock
  mid-steady → `WATCHDOG-CONTAINER-DEAD` → clean teardown within ~60 s; unreachable
  upstream → k6 exits 99. Attempt #1's first 220 collector rows (~110 min pre-OOM) are kept
  as a partial data point only, not as pass evidence.
- **Harness incident (scenario levers silently no-op'd; no product deviation).** Attempt #2's
  four WireMock-scenario faults (2 vendor-429, 3 vendor-5xx, 6 rotate, 7 clock-skew) never
  executed. Evidence: `faults/fault-log.txt` records `curl: (22) ... error: 404` at every
  scenario flip while the lever still printed success; the post-reset window journals contain
  100 % 200s with baseline volumes (no 429/500/skew anywhere); the KV stub response body hash
  is identical in all 18 captured windows (rotation never happened). Cause: WireMock 3.9.2
  has no scenario-force endpoint (`POST /__admin/scenarios` answers 404), forced state cannot
  even be restored by `PUT /__admin/scenarios/<name>/state` (only `possibleStates` values are
  accepted — `Started`/`normal` are not), and the lever hid its own failure twice over: the
  shell function's last command was a bare `echo`, and the runner piped the lever through
  `tee`, swallowing the exit code (a recurrence of a known class). Classified **harness
  error** — the faults were not observed, so no product judgement attaches either way. Fixed
  in 59cb3f9: loud stub-swap lever (POST priority-override copy / DELETE persisted id), lever
  exit codes no longer piped away, scenario-gated startup mappings stripped in the re-run
  driver (forced state is unrecoverable in 3.9.2). All four swaps sabotage-probed live before
  relaunch: 429 + `Retry-After: 5` and 500 flip and restore to clean 200; skew mints serve
  `expires_in: -30` and restore positive; the rotated KV body deep-equals its stub file and
  restores to kv1. Re-run: `scripts/phase-b2.sh` — the first launch (dir `m33-soak-20261109-074851`)
  aborted at fault-2's CLEAR step on a follow-up harness bug in the dropstub helper (single-statement
  `local a=..$a..` expansion under `set -u`; fixed in 791503b — and the abort itself proved the new
  exit-code plumbing works: the aborted window journal shows the swap had served 20 101 x 429 with a
  healthy IdP/KV). Completed run: dir `m33-soak-20261109-075813` (07:58–08:47Z, `PHASE-B2-DONE`,
  zero WARN lines). Results: §4 rows 2/3/6/7. Process lesson: the green-marker doctrine was applied
  to the run's abort paths before launch but not to the fault levers themselves — lever verification
  now prints `swap-on/swap-off` markers that the driver asserts.
- **Harness errors (B2; no product judgement attaches to the unverified behaviours).** Three levers
  ran live but did not reach the behaviour they were pre-stated against:
  1. *fault 2 pause + fault 3 breaker — features never wired.* Both are opt-in registration
     (`AddCredProxThrottling`, `AddCredProxResilience`; the features are documented inert otherwise)
     and `tools/m33-soak/SoakHost/Program.cs` calls neither — yet the run's `host-config/appsettings.json`
     carries populated `Throttling`/`Resilience` sections, which bind only inside those calls. Latent
     second defect: the config keys clusters `cc`/`gen1` while every soak route uses `ClusterId: vendor`,
     so even wired, the per-cluster overrides (0.5/10 s/5 s; 100 permits/s) would not have matched.
     Evidence: `journal-2-window.json.gz` (20 103 x 429 with `Retry-After` untouched, 1:1 volumes),
     `journal-3-window.json.gz` (20 103 x 500, 1:1), `host-2.log`/`host-3.log` (0 warn/err/category
     lines). Consequence: "pause ≈ Retry-After then lifts" and "breaker opens/half-opens/closes"
     remain UNVERIFIED in this soak; they are covered by unit suites, not by this battery.
  2. *fault 6 rotation — lever too shallow.* The provider reloads via `GET /secrets/` (list) and
     re-fetches a secret only when its `attributes.updated` changes; the lever swapped only the
     per-secret GET stub (`kv_gen2_kv2`), while `kv_list` pins `updated: 1730000000` — so the
     provider never re-fetched (journal: 30 list polls/window, **0 per-secret GETs** in window and
     recovery; poll bodies byte-identical). This is the documented M29 trap ("KV stub must bump
     `attributes.updated`") recurring in a new harness. Consequence: next-mint rotation semantics
     UNVERIFIED in the soak battery (the M29 offline-proof battery covers the provider path itself).
  B3 (maintainer-approved 2026-11-09, harness commit d664f8b): both opt-ins wired in
  `SoakHost/Program.cs`, both config sections rekeyed to the `vendor` cluster, rotate lever
  extended to swap `kv_list` with a bumped `updated`; faults 2/3/6 re-run (~30 min, dir
  `m33-soak-20261109-101912`, `PHASE-B3-DONE`, `FINAL-SCAN-ZERO`, teardown clean, zero WARN
  lines). Each lever was sabotage-probed against its TARGET behaviour before launch (pause =
  429 without vendor hit; breaker 503 shape; one per-secret GET after the flip) — the probing
  also caught a stale-publish chain (runtime-only COPY Dockerfile), so the phase script now owns
  publish → build → force-recreate. Rows 2/3/6 above now carry B3 verdicts. Residual limit
  introduced by the battery itself: no k6 scenario drives route `gen2`, so fault 6's
  attach-layer value walk rests on the pre-launch probe, not on battery traffic.
- **Product deviation (fault 7 clock skew; library bug — fixed in 0fcfe96).**
  Observation: under `expires_in: -30` the token cache stopped refreshing (1 mint in the skewed window,
  0 in recovery vs 10/window baseline). Cause in shipped code: `OAuthClientCredentialsProvider.ReadLifetime`
  (`src/CredProx/Credentials/OAuthClientCredentialsProvider.cs:180-182`) maps any non-positive `expires_in`
  to `DefaultLifetime` (1 h) — a defensive default documented for *absent* fields, silently applied to
  *past-expiry* ones, caching the dead token for an hour. Against the pre-stated expectation
  ("near/past-expiry tokens refresh") this is a FAIL: a misbehaving IdP would put the cluster into a
  1-hour window of serving tokens the real vendor will reject; the soak's echo vendor cannot expose the
  downstream 401s (stated limit), but the cache behaviour is observable directly (mint collapse).
  Per the row's rules this class needs src fix + regression test + §5.3 gates; the fix direction
  (clamp past-expiry lifetimes toward immediate refresh vs reject) is a design call — deferred for
  maintainer review with evidence: `journal-7-window.json.gz` (1 mint, negative body), `journal-7-recovery.json.gz`
  (0 mints), all B2 windows' baseline 10 mints elsewhere.
  **Design decision and fix (commit 0fcfe96, 2026-11-09):** reject was chosen over clamp — a negative
  `expires_in` (number or numeric string) is a protocol violation, rejected through the documented
  IdP-failure path (`credential_unavailable` 502, nothing cached, one warning naming the field and
  credential id, never the value); `expires_in: 0` keeps `DefaultLifetime` (IdPs use 0 for "no stated
  expiry") and now logs once per credential; absent/non-numeric unchanged. Regression tests cover
  negative number/string (rejected, cache-empty asserted against the negative-cache backoff:
  re-throw without a vendor hit inside the TTL, re-mint after), 0 (one warning per credential),
  1 s (refreshes on schedule), absent and garbage. Full §5.3 gates green: build 0 warnings, all
  CI suites passed (1 680 tests), core coverage 98.2 % line / 93.7 % branch, fresh-obj pack with
  APICompat clean against the 0.8.2 baseline, and the token-cache-hot-path sample smokes
  (E8/E9/E10/E13) re-run against the repacked bytes after local-feed cache eviction.
  Patch-level behaviour fix; CHANGELOG Unreleased (Fixed).

## 6. Not covered (honest list; from README "Known gaps" + run observations)
- Throttle pause on vendor 429, circuit-breaker open/half-open/close lifecycle, and live KV
  rotation were uncovered in the first two attempts and are now covered by B3 (§5 entry 3;
  §4 rows 2/3/6) — with one residual gap: no k6 scenario drives route `gen2`, so the rotation's
  attach-layer value walk rests on the pre-launch sabotage probe rather than battery traffic.
- SSE stub emits a finite event burst (WireMock cannot drip indefinitely); fault 4 covers the reset
  path on a live body, a long-lived stream is covered only by k6 read timing.
- Clock skew uses a negative-lifetime token (`expires_in: -30`); a *future*-skewed variant needs
  container clock control and is deliberately out.
- Fault 6 runs the real provider path per the design decision; the config-file rotation survives
  only as the secondary witness inside fault 5 (`reload-mix`).
- LoginExchange placement header asserted via both `X-Session` and `Authorization` echoes; the
  smoke pinned the credential on the `Authorization` header (vendor-side journal echo: auth
  present, session absent on the login route).
- Not covered by anything: multi-instance behaviour (shared token cache semantics across hosts),
  real Azure AD latency/redirect behaviour, Kestrel TLS/HTTP2 transport faults, GC modes other
  than Server (container default), long-lived (>4.5 h) drift beyond this soak window, and
  Windows/Linux socket-limit differences beyond this host's Kestrel config.

## 7. Nightly proposal (NOT wired)
A shortened nightly — smoke topology, ~20 min soak at half rate, faults 1b+2 only — would catch
boot-path and hot-path regressions the unit suites miss; mutation/fuzz stays as designed in §5.4.
Wiring decision belongs to the plan owner.
