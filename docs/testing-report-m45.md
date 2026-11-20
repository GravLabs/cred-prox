# M45 testing report — 4-hour soak, VOID: the run authenticated nothing

**Status: this run provides ZERO coverage of the proxied path.** The 2026-11-19
FULL soak ran end-to-end green and is, on inspection, worthless as product
evidence: every one of its 993,604 caller requests was refused with
`401 "No caller API key was presented"`. Nothing was ever proxied. This report
states what happened and what the numbers actually describe; a valid re-run on
the fixed harness is the next step, and until it lands no M45 soak coverage
claim stands — for the tested bytes or for the release tip. The superseded
version of this file presented the run's PASS marks as results; that version
shipped at commit `eb6bd3d` and is replaced wholesale by this one.

## 1. What the run actually did

Run: `tools/m33-soak` FULL mode (`scripts/run-soak.sh`), 2026-11-19
13:53:25Z → 17:53:56Z, run dir `m33-soak-20261119-135325`, tested bytes
`e9f3d59` (branch `m45`, before the security merge `691a484`).

- Caller authentication is enforced in `SoakHost` since `568a398` (13:44Z the
  same day — nine minutes before this run started). The harness sends its
  caller key under `x-api-key`; the caller-key authenticator reads
  `CallerKeyOptions.HeaderName`, which defaults to `X-CredProx-Key`
  (`src/CredProx.CallerKeys/Callers/CallerKeyOptions.cs:25`, checked at
  `CallerKeyAuthenticationHandler.cs:46`), and nothing in `tools/m33-soak` or
  the generated run config set `CredProx:CallerAuth:HeaderName`. Every
  request therefore failed at the caller-auth stage, before routing,
  credentials or scrubbing. The key VALUES were correct (each run key hashes
  to its configured `KeyHash`); the header NAME was the defect.
- Evidence: `logs/soakhost.log` contains exactly 993,604 lines
  "Not Proxying, a 401 response was set by the transforms." and 1,987,210
  "CredProxCallerKey was not authenticated" lines — TWO per refused iteration
  plus the 2 boot-window lines (2 x 993,604 + 2), not one per iteration
  (`iterations.count = http_reqs.count = 993,604`). Mean response 313 B — a
  401 body, not an echoed vendor payload.
- `journal/wiremock.json`: 1,444 requests, 1,443 of them the Key Vault stub
  poll `/secrets/?api-version=7.5` plus one secret read. Zero
  `/cc/echo`, `/gen1/echo`, `/login/prod/login`, `/sse/stream` or
  `/idp/token` calls: no vendor or IdP call was ever proxied.
- The 13:53Z smoke run that preceded it has the same shape: same harness,
  same header, 100 % refusals.

Consequences for the claims the previous version made: a scrub witness over
401 bodies is vacuous (no caller ever received a body that could carry a
secret); the secret scan over the run's outputs is likewise vacuous for leak
coverage; the token-cache "99.85 % absorption" arithmetic was KV-polls over
rejected requests and described nothing.

## 2. Why every gate stayed green, and what now catches this

The CSV failure-rate column derived from k6's `http_req_failed`. In k6 1.x
that metric is transport-only: on the digest-pinned v1.4.0 image, two
successful GETs plus one connection-refused GET still report
`{passes: 3, fails: 0, rate: 1}` — an HTTP 401 is not a transport failure, so
a 100 %-401 run writes "failed=0". The `LOAD-GATE` read only that column plus
the scrub counter, so it could not fail on this shape. The previous version of
this report additionally stated the script "defines no per-iteration k6
check()" — false on its face: `k6/soak.js` has one status-200 check per
scenario, and their tally (`passes: 0 of 993,604`, rate 0) is exactly the
signal that contradicted the green gate. It was discarded instead of read.

Fixed in this round: `k6/soak.js` now writes the literal `checks`
passes/fails into the summary line, and `scripts/load-gate.sh` (replayable
against any run dir) gates on — checks fails == 0 AND checks passes ==
iterations > 0; zero transform-set 4xx/5xx refusals and zero caller-auth
failures in the host log; and a positive journal count for every scenario's
proxied path plus at least one IdP token call. Replaying this run's artifacts
through the new gate reports `LOAD-GATE-RED` with all five reasons; the old
gate on the same artifacts printed `LOAD-GATE-OK`.

## 3. What was mechanically measured (all of it on a rejected-request load)

These numbers describe the harness and the host under 69 rps of 401 refusals.
They are not proxy-path results and none of them supports a coverage claim.

- Arrival-rate control held: 993,604 iterations over k6's own
  `testRunDurationMs = 14,400,002` (exactly 4 h → 69.0002 it/s, matching the
  summed 40+25+2+2 arrivals; the driver window 13:53:25Z→17:53:56Z is wall
  clock including startup — the two clocks differ by ~31 s). `vus_max` 22,
  never past pre-allocation.
- Collector (`stats.csv`, 481 samples = 480 intervals at 30 s; row 1 is the
  pre-load baseline 86.5 MiB RSS / 3.8 MiB heap / 18 threads): first loaded
  sample RSS 117.5 MiB → last 120.7 MiB, last-2 h slope +1.39 MiB/h, peak
  128.2 MiB; heap 8.4 → 9.6 MiB; threads 19–23. A steady host serving
  constant-arrival 401s — plausible for the refusal path; says nothing about
  the proxied path.
- Latency (median 0.26 ms, p95 0.86 ms) is refusal latency, not proxy
  latency.

## 4. Consequences — and the valid re-run that closes them

- The authenticated caller-key → proxy path had NO soak coverage at any
  commit: the 13:53Z run above proved nothing, and the earlier M33 runs predate
  caller-key enforcement entirely (see the dated correction note in
  [testing-report-m33.md](testing-report-m33.md)). That absence ended with the
  fixed-harness re-run below, which completed 2026-11-19.
- **The re-run, real numbers** (run `m33-soak-20261119-190916`, driver 19:09:16Z
  → 23:10:08Z, product bytes `0.14.0-dev+d82b1e4` stamp-verified before launch,
  harness scripts `0b146fd`; every tip commit after that stamp touches only
  harness scripts, tests and docs — no product code).
  Workload: 993,599 iterations in k6's own 4 h 00 m 00.0 s run window →
  `iterations.rate` = 69.0000 it/s on that named clock; the driver window
  (4 h 00 m 52 s, setup+teardown included) gives 68.94 it/s — quote one and
  name it, the clocks differ by ~52 s. `vus_max` 24, never past pre-allocation.
- **The proxied path is proven, cumulatively.** Whole-run host-log counts (the
  WireMock journal is a newest-kept ring — at ~67 vendor req/s it covers only
  the last ~7.5 min, so whole-run claims ride the host log, never the ring):
  `Proxying to` lines 993,599 — exactly the iteration count — with the scenario
  buckets cc 575,999 + gen1-path 388,800 (gen1 and login scenarios) + sse
  28,800 summing to that total exactly; vendor-side IdP token POSTs 480 (one
  per 30 s refresh) and login-exchange POSTs 160 (one per 90 s) through the
  proxy — the token cache absorbing the load is the measured mechanism, not an
  assumed one. Transform-set refusals 0; scrub misses 0; k6's literal
  per-request status-200 checks 993,599/993,599. Caller-auth failure lines: 2,
  both logged at host boot before the first proxied line (boot-window probes,
  inside the gate's login-call budget) — they are visible on the replayed gate
  line below rather than printed away. Last-window journal ring: cc 17,355,
  gen1 11,714, sse 867, login 5, idp 14 (the replayed read saw cc 17,354 —
  one oldest entry was pushed out by a continuing Key Vault poll after k6
  exited; disclosed, host-log cumulatives unaffected).
- Collector (`stats.csv`, 481 samples = 480 intervals at 30 s; row 1 is the
  pre-load baseline 86.4 MiB RSS / 3.8 MiB heap / 18 threads): first loaded
  sample RSS 137.7 MiB / heap 26.4 MiB / 23 threads — the ramp is also the
  peak; last sample 125.8 MiB / heap 10.3 MiB / 20 threads; last-2 h slopes
  +0.124 MiB/h RSS and +0.078 MiB/h heap: flat within sampling noise, no leak
  signature on the proxied path (contrast §3's refusal-path record).
- Proxied-path latency: median 5.33 ms, p95 20.35 ms, p99 205.68 ms, max
  435.61 ms (the p99 tail carries the sse scenario's stream lifetimes; §3's
  sub-millisecond figures are refusal latency and no longer a comparable).
- Both gate lines, version-labelled: the driver line carries gate semantics as
  of `ebd79dd` — no host equality term — and is NOT attributed whole-run
  coverage; the claim-bearing line is the replay at the fix commit `18eb2ef`
  on the same run dir (adds host-proxy equality and the cumulative mint/
  exchange terms, prints every measured value), RC=0:
  - driver: `LOAD-GATE-OK checks_pass=993599/993599 host_refusals=0 caller_auth_failures=0 journal[cc=17355 gen1=11714 login=5 sse=867 idp=14] scrub=0`
  - replay `18eb2ef`: `LOAD-GATE-OK checks_pass=993599/993599 host_refusals=0 caller_auth_failures=2 host_proxy_total=993599 host_mints=480 host_exchanges=160 journal[cc=17354 gen1=11714 login=5 sse=867 idp=14] scrub=0`
  and `SECRET-SCAN-OK (zero hits)`. The run record lives on ephemeral disk
  (`m33-soak-20261119-190916` under the soak root); its end-of-run derivation
  and this line pair are kept with the milestone build evidence.
- Scope for release: the release candidate's `src` is byte-identical to the
  security merge `691a484` (`git diff 691a484 d82b1e4 -- src` is empty), so
  this run soaked exactly the src the patch release carries. The release-prep
  check is therefore the ~10-minute start-and-pass smoke through the fixed
  gate at the release tip, not a repeated long soak (decision recorded on the
  release row, 2026-11-19).
- Honest limits that survive: the harness topology, stub set and collector are
  sound (they produced a clean, consistent record of their own failure first);
  the journal ring cannot speak for the pre-last-window part of any long run —
  cumulative host-log terms do; the boot-window auth probes are harness noise
  inside the gate budget, not product behaviour; and the soak's vendor is the
  stub IdP/vendor pair behind toxiproxy, not a live third party.
