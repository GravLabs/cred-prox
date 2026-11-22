# M33 soak + failure-injection harness (plan §5.5)

Runs the **repository's current CredProx** — the version this tree packs, from the local
feed, not `src/` project references — under sustained load behind Toxiproxy,
against WireMock stubs, inside the §5.5 machine budget: Σ container caps 6.0 CPU / 3.75 GiB,
`uptime` sampling every ≤60 s (run-soak.sh; 30–60 min in the phase drivers) with backoff when the 5-min load passes `SOAK_LOAD_LIMIT` (default 40):
the run then stops its own label-tagged k6 one-off and reports a named load-gate failure
(BACKOFF-GATE-FAIL), never a pass. Teardown runs on every exit path —
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
| `scripts/` | `init-secrets.sh` (per-run sentinels + hashed caller keys) · `stamp-guard.sh` (image-bytes provenance; refuses a host image whose `CredProx*.dll` or `SoakHost.dll` stamp is not this checkout's commit) · `run-soak.sh` (runner + watchdog + teardown trap) · `faults.sh` (levers, each prints its pre-stated expectation) · `secret-scan.sh` (zero-hit doctrine) · `slowloris.py` (bounded) · `teardown.sh` |

## Before the first run

1. Pack every package the host consumes into the feed: `dotnet pack src/CredProx.Abstractions
   -c Release -o artifacts/packages`, then the same for `src/CredProx`, `src/CredProx.Operations`,
   `src/CredProx.OAuth` and `src/CredProx.LoginExchange` (Abstractions is a transitive package the
   feed must carry, or the restore fails NU1101 on it; Operations/OAuth/LoginExchange are the
   packages the host's registrations and its credential Types name — ADR-0005 moved them out of
   the core, and startup validation refuses a config that names a Type without its package;
   `SoakHostCredentialPackagePinTests` keeps this list and the config from drifting apart).
   Same flow as `samples/nuget.config`, and CI packs every package before building.
2. Publish on the host, then build the runtime-only image (host NuGet cache carries the
   Azure KV provider closure; the image is a pinned aspnet copy of the publish output).
   For release-shape runs, isolate the restore: a `credprox*` id+version already unpacked
   under `~/.nuget/packages` counts as installed, so a repacked `.nupkg` on the feed is
   silently ignored and the host would run bytes this tree did not pack. An EMPTY
   `RestorePackagesPath` is not the lever — the centrally-pinned dependencies cannot
   restore from the feed alone, so the publish fails. Clone the warm cache and delete just
   the packages under test (hardlinks leave the real cache untouched), then point the
   restore at the clone:
   `cp -al ~/.nuget/packages/. <clone> && rm -rf <clone>/credprox*`
   `dotnet publish tools/m33-soak/SoakHost -c Release -o tools/m33-soak/build/publish -p:RestorePackagesPath=<clone>`
   `docker build -f tools/m33-soak/SoakHost/Dockerfile -t credprox-soakhost:local .`
3. Pull the pinned proxies once if absent: `docker compose -f compose/docker-compose.yml pull` (run from this dir with `SOAK_RUN_DIR` set to any scratch dir just for validation).

## Run

Before a soak, at the candidate SHA: pack, then publish, then `docker build` — every
new commit invalidates the existing image even when `src/` did not change (the stamp
names the commit), and rebuilding only some layers is the fresh-libraries-plus-stale-host
state the guard exists to catch.

The runner's first act is the provenance guard (`stamp-guard.sh`): it reads the
`CredProx*.dll` and `SoakHost.dll` files out of the soakhost image compose would start
and requires each one's InformationalVersion to name this checkout's commit —
`STAMP-GUARD-OK`, or a `STAMP-GUARD-FAIL` naming the expected and found stamps, printed
before any container is created. The runner keeps the guard's output and writes it into
the run dir as `stamp-guard.log`, so a preserved run dir is self-attesting. Run it
standalone to check the tag without starting anything:
`tools/m33-soak/scripts/stamp-guard.sh`.

```bash
SOAK_RUN_DIR=... # the runner creates its own /tmp/m33-soak-<utc> dir and exports this itself
SOAK_LOAD_LIMIT=40 # 5-min-load backoff threshold (every run-soak/phase-b* driver); set -1 to force the backoff branch on a short run
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
