# M33 soak + failure-injection harness (plan §5.5)

Runs the **published CredProx package** (not `src/`) under sustained load behind Toxiproxy,
against WireMock stubs, inside the §5.5 machine budget: Σ container caps 6.0 CPU / 3.75 GiB,
hourly `uptime` check with backoff at 5-min load > 40, and teardown on every exit path —
no container outlives a scenario, clean or failed.

**Phase A status: scaffold — not yet executed.** First action of Phase B is the `--smoke`
run (3 min) below, then the 4 h steady soak and the fault sequence, only after the plan
owner's OK.

## Layout

| Path | What |
|---|---|
| `SoakHost/` | the proxy under test: CredProx pipeline + stats collector (RSS/GC/threads/sockets CSV); config-only, mounted live for reload faults |
| `compose/` | digest-pinned topology with CPU/mem caps; only localhost-bound ports (host 18080, WireMock admin 18081, Toxiproxy API 8474) |
| `wiremock/mappings/` | stub IdP + stub vendor templates (echo of received secrets for scrub witnesses, SSE stream, 429/5xx scenarios, skew token) |
| `k6/soak.js` | bounded mixed workload (cc/static/login/SSE) + caller-side scrub witness |
| `scripts/` | `init-secrets.sh` (per-run sentinels + hashed caller keys) · `run-soak.sh` (runner + watchdog + teardown trap) · `faults.sh` (levers, each prints its pre-stated expectation) · `secret-scan.sh` (zero-hit doctrine) · `slowloris.py` (bounded) · `teardown.sh` |

## Before the first run

1. `dotnet pack src/CredProx -c Release -o artifacts/packages` (feed for the host, same
   flow as `samples/nuget.config`).
2. Publish on the host, then build the runtime-only image (host NuGet cache carries the
   Azure KV provider closure; the image is a pinned aspnet copy of the publish output):
   `dotnet publish tools/m33-soak/SoakHost -c Release -o tools/m33-soak/build/publish`
   `docker build -f tools/m33-soak/SoakHost/Dockerfile -t credprox-soakhost:local .`
3. Pull the pinned proxies once if absent: `docker compose -f compose/docker-compose.yml pull` (run from this dir with `SOAK_RUN_DIR` set to any scratch dir just for validation).

## Run

```bash
SOAK_RUN_DIR=... # the runner creates its own /tmp/m33-soak-<utc> dir and exports this itself
tools/m33-soak/scripts/run-soak.sh --smoke              # 3 min smoke (Phase B step 0)
tools/m33-soak/scripts/run-soak.sh                      # 4 h steady soak (240 min, 20 VUs)
SOAK_RUN_DIR=/tmp/m33-soak-... tools/m33-soak/scripts/faults.sh vendor-429 set
# ...30 s window + recovery watch (k6-line.csv error rate + stats.csv sockets band)...
SOAK_RUN_DIR=/tmp/m33-soak-... tools/m33-soak/scripts/faults.sh vendor-429 clear
```

Order: 1 idp-slow/idp-down → 2 vendor-429 → 3 vendor-5xx → 4 reset-mid → 5 reload-mix →
6 rotate → 7 clock-skew → 8 slowloris (per §5.5 estimate). Expectations are printed by each
`set` and must match the plan table — plan text is authoritative, script text is a reminder.

## Run directory (never committed)

`/tmp/m33-soak-<utc>/`: `host-config/appsettings.json` (live-edited) · `keys.txt` +
`sentinels.txt` (plaintext secrets, run-local) · `stats.csv` (host collector) ·
`k6-line.csv` + `k6-summary.json` · `journal/wiremock.json` · `logs/soakhost.log` ·
`faults/` (per-fault log slices, Phase B) · `secret-scan-hits.txt`.
`secret-scan.sh` requires zero sentinel hits in the PRODUCT's own outputs (host logs, k6
caller-side files, stats, fault slices). The WireMock journal is the vendor-side wire
witness and by design carries raw stub values on the wire (M20 scrubbed-echo doctrine);
the caller-side witness is the k6 `noSentinelInBody` check.

## Known gaps (named for review)

- Fault 6 runs the real provider path per the 2026-11-08 design decision (`rotate` flips the KV stub
  value + `attributes.updated`; provider polling is what must catch it). The config-file
  rotation lives on as the secondary witness inside `reload-mix`.
- SSE stub emits a finite event burst (WireMock cannot drip indefinitely); mid-stream reset
  (fault 4) therefore exercises the reset path on a live body but a long-lived stream is
  better covered by k6's own read timing - refine in Phase B if the witness is thin.
- Clock skew uses a stub IdP returning `expires_in: -30` (negative-lifetime token);
  a *future*-skewed variant needs container clock control and is deliberately out.
- LoginExchange placement header name is asserted via both `X-Session` and `Authorization`
  echoes in the stub - first smoke pins which one the credential uses.
