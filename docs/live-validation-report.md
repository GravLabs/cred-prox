# Live validation report (M26 + M29 round 2)

**What this document is:** the evidence log of the live validation runs — a test
record, not user guidance. Scripts: `scripts/live-azure-smoke.sh` (plan:
`docs/azure-live-test-plan.md`; round-2/M29 sections: the Round 2 block below). Discipline: outcomes, status codes and
resource **names/roles** only — no secrets, no tenant/subscription GUIDs, no
response bodies. Scratch responses are kept in `/tmp` and deleted after each
run.

## Findings surfaced by the battery

- **E5 env-override fix (sample, not `src/`)**: `--variant identity` loaded
  `appsettings.ManagedIdentity.json` *after* the default env-var provider, so
  `CredProx__Credentials__graph__Scope` overrides silently lost to the file —
  the exact "config key resists env override" exception the plan names as the
  one allowed delta. Fixed by re-adding env + command-line sources after the
  variant file, mirroring the OAuth branch. Phase 1's ARM-scope override
  passing is the proof the fix bites.
- The sample pins `UseUrls("http://localhost:5085")` (documented in its
  README); the battery targets 5085 rather than overriding.
- **Transient argv exposure of the live client secret (battery scripts,
  2026-11-04 — disclosed, verified, fixed):** phase 4's E-mode vault seed
  passed the real secret as a `--value` **argument**, so it was readable from
  `/proc/*/cmdline` by any local process for the lifetime of the `az` process.
  The Phase 5 cycle run took this path (08:06:33Z, per `~/.azure/commands`);
  az's command log redacts arguments to `{}`, so **nothing was persisted to
  disk** — the exposure was transient and local to this machine, and the value
  was one the battery legitimately held (same approved credential).
  Fixed: the seed now uses the pipe channel `--file <(printf '%s' …)`, the
  same shape as the version-pipe restore, so no argv path carries the real
  secret even in E mode. A grep over the whole battery for secret-taking
  flags found the remaining cases: the wrong-value overwrite `--value` is a
  fixed dummy (not a secret), and the proxy handoff `env
  CREDPROX__Secrets__graph-client-secret=$SECRET dotnet run` is the same
  transient-argv class — inherent to the one working channel for a dotted
  config key that is not a valid bash identifier, visible in the `env`
  process's cmdline only while the proxy is alive, never logged. Post-fix the
  battery re-ran in **V mode** (holds no value anywhere): all phases PASS.

## Tenant-environment findings (wiring window, Oct 31 – Nov 3)

Recorded from the Phase 3 setup attempts before the phase was dropped (all
verified live against the maintainer's tenant; objects since deleted):

1. **Key Vault creation in the RG's home region is rejected by this tenant**
   (`RequestDisallowedByAzure`, location ineligible) — the vault lives in
   `northeurope` instead.
2. **This tenant's Graph strips `publicClient.enabled` on write** (v1 *and*
   beta, raw-request proven: "Expected property 'enabled' is not present",
   even for `false`). A device-code *public* client per the plan is not
   achievable here; the test client ran as a confidential client with a
   locally-held secret (device-code flow still works, still consent-free).
3. **Newly created delegated scopes default to `type=Admin`** in this tenant's
   Graph, which makes a user device-code sign-in fail as admin-consent-only;
   scopes must explicitly be created/patched `type=User`.
4. **`az ad app create` does not auto-provision service principals here**
   (verified ~45 min after creation: both absent), and `az ad app update
   --set` fails on app-schema writes (`publicClient=…`, `api.…`) —
   `--is-fallback-public-client` silently no-ops. App property writes need a
   Graph PATCH via `az rest`; a bare PATCH **replaces the whole `api`
   object**, so GET-and-merge first.

## Runs

### 2026-10-30 — CI-parity dry run (unauthenticated host)

`AZURE_CONFIG_DIR=<empty> scripts/live-azure-smoke.sh` →
`no az sign-in -> all phases SKIP (CI parity)`, exit 0. Phases 1–4 SKIP
without touching anything: the battery is safe next to CI's `smoke.sh` set.

### 2026-10-30 — teardown dry run

`scripts/teardown-live-test.sh --dry-run` → all three `credprox-e14-*`/
`credprox-e5-oauth` registrations **absent**, resource group
`credprox-live-test` **absent**: the tenant carries no credprox objects
before Phase ≥2 setup. Read-only (list/show only).

### 2026-10-30 — Phase 1: PASS (first live-Azure proof for this project)

`scripts/live-azure-smoke.sh 1` on the maintainer's machine with the existing
`az login` session (no sign-in performed by the battery, no tenant mutation,
no resource creation — the ARM call is the authenticated-user
`GET /subscriptions` list):

- proxied `GET …/subscriptions?api-version=2022-12-01` through CredProx →
  **200**, repeat → **200**, JSON body confirmed, forwarded to
  `management.azure.com` with the CredProx-injected bearer;
- credential: `TokenCredential` type over `DefaultAzureCredential` — the
  secretless path `CredProx.AzureKeyVault` ships — with
  scope `https://management.azure.com/.default` supplied purely by env
  override;
- **zero secret material** in the configuration set or any output.

Limit (honest): proxied-token single-flight was not re-counted here — the
provider's single-flight is covered by `FakeTimeProvider` tests; over the
real chain `DefaultAzureCredential` adds its own cache, so a 2-call probe
cannot attribute the reuse. The originally planned attribution venue —
Phase 3's live exchange counted per `x-ms-request-id` — was **dropped with
the phase** (decision 2026-11-03; OBO removed in M27), so no live-issuer
issuance attribution exists anywhere in this milestone; the fake-level
proof stands alone.

### 2026-10-31 — Phase 2: PASS (client-credentials vs real Entra + live scrub)

Maintainer-authorized tenant objects in place (resource group
`credprox-live-test`, app registration `credprox-e5-oauth` with its service
principal holding Reader on that RG). `scripts/live-azure-smoke.sh 2` on the
maintainer's machine with the existing `az login` session:

- positive run: OAuth (client-credentials) variant; CredProx minted a real
  `…/oauth2/v2.0/token` token from the tenant and proxied
  `GET …/subscriptions?api-version=2022-12-01` → **200** with the injected
  bearer;
- negative run on a **fresh** proxy restart configured with a deliberately
  wrong secret: Entra refused the mint (**401** at the token endpoint,
  `invalid_client`), CredProx answered the caller **502**
  (`application/problem+json`) per §3.4 — and the caller-visible body
  carries **no secret material** (prefix grep over the scratch response);
- secret hygiene: the client secret was rotated for this run via
  `az ad app credential reset` (each sandbox run re-rotates), accepted only
  through `CREDPROX_LIVE_CLIENT_SECRET`, passed to the process via the
  environment channel; never printed, never on a command line visible in
  logs (the env handoff is transiently visible in the `env` process's argv —
  see the argv finding above; nothing persisted); the library's own warning
  line names the credential and the HTTP status, no secret echo.

Battery fixes this run proved out (commits `3e43f09`, `6f41ef0`): the dashed
config key `CredProx:Secrets:graph-client-secret` is not a valid bash
identifier — `export` silently fails on it, so the battery now passes the
secret via `env NAME=value`; and the negative probe restarts the proxy (a
running process never re-reads env, so re-exporting would have probed the
*old* secret — a dishonest-green hole).

### 2026-11-04 — Phase 4: PASS (Key Vault as the only secret source; rotation by OVERWRITE)

Second maintainer go-ahead (04:06Z) chose option (b) and delegated
execution — the 03:02Z first go-ahead had STOPped at its own precondition (the Phase 2
client secret was not available locally; history in the M26 row's transitions).
Authorized exactly: **one** `az ad app credential reset` on `credprox-e5-oauth`
with `--append --display-name credprox-m26-p4 --end-date 2026-12-04` (existing
credential kept), its output piped straight into `az keyvault secret set` —
value never printed, never in argv, never on disk.

- Pre-run baseline: vault `credprox-live-kv` empty (zero secrets);
  `credprox-e5-oauth` carried one password credential.
- Post-seed read-back: two `passwordCredentials` — the new one named
  `credprox-m26-p4`, end date 2026-12-04, plus the kept existing one; the vault
  secret held exactly one version.
- `scripts/live-azure-smoke.sh 4`, **V-mode** (no env secret anywhere):
  - vault-only start → real Entra mint **200** → proxied ARM
    `GET …/subscriptions?api-version=2022-12-01` **200**; the secret entered the
    process only from the vault — nothing on disk, nothing in the passed env;
  - **rotation by OVERWRITE**: vault value replaced with a wrong dummy → fresh
    start → Entra refused the mint (**401**), CredProx answered the caller **502**
    `application/problem+json` (`credprox.credential_unavailable`) — the
    caller-visible body is the fixed error shape with no secret echo (V mode:
    the battery never holds the value, so the echo claim is honestly scoped to
    that shape; the library's warning line names the credential and the HTTP
    status only);
  - **recovery**: previous version's value restored through a bash FIFO
    (`az --file <(show --id <prev> | tr -d '\n')` — value again never printed,
    never in argv, never on disk) → fresh start → **200**.
- Post-run: the vault secret carries three versions; the **current** version holds
    the correct value. Rotation is proven by OVERWRITE, not delete+re-add —
    soft-delete's name lock makes the latter unusable.
- The go-ahead's UAI-grant item stayed moot (no test UAI exists — finding 4/§ above);
    the vault's RBAC carries the maintainer's account as **Key Vault Secrets Officer**,
    which covers this run's CLI-identity reads. No grant changes, no other tenant
    mutation.

### 2026-11-04 — Phase 5: destroy → apply → re-run cycle: PASS (one-command IaC proven)

Maintainer go-ahead "go cycle" (12:21Z): run the five commands at
`f51d43b` in order, stop at first failure. The cycle **destroyed and rebuilt
the tenant objects end to end** and re-passed the battery:

- Pre-cycle baseline: old app carried 2 credentials; vault secret had 3 versions.
- 1) `live-e5-app.sh destroy` — role grant deleted **before** SP + app (the
  orphan-avoidance order from review); clean.
- 2) `live-infra-destroy.sh` — vault deleted and **PURGED** (read-back: PURGED;
  the old vault predated any purge protection, purge protection is null).
- 3) `live-infra-apply.sh` — **two stops, both template bugs, no design change**
  (each stopped, reported, resumed on the maintainer's go-ahead):
  (a) `enablePurgeProtection: false` is rejected at create on every
  subscription — off is expressed by **omitting** the property;
  (b) a from-memory Secrets Officer role GUID failed with
  `RoleDefinitionDoesNotExist` — the apply script now resolves the role
  definition id **live** (`az role definition list`), no GUID in the tree
  . Both fixes were verified read-only before each go-ahead.
  Apply then succeeded; read-backs: vault `enableRbacAuthorization: true`,
  `enablePurgeProtection: **null**` (omission = off, proven at the resource),
  soft-delete retention 7; vault-scope role assignment list = exactly one,
  Secrets Officer for the maintainer.
- 4) `live-e5-app.sh create` — new registration (different application id),
  SP + RG Reader recreated, fresh 30-day credential (`credprox-m26-p4`) piped
  into the fresh vault (value never printed/argv/disk). Read-backs: exactly one
  `passwordCredentials` entry (the new one); RG has exactly one role assignment
  (the new SP) — **no orphaned Unknown principal from the deleted SP**; vault
  secret = 1 version.
- 5) Battery `1 2 4`: all PASS — P1 secretless 200s; P2 live mint 200 + wrong
  secret refused with clean `problem+json`, no echo (the vault-fetch fallback
  made this work with no exported env); P4 vault-only 200 → wrong overwrite →
  502 no echo → version-pipe restore → 200.

Honest nuance from the run: the phase-2 fallback initially wrote
`CREDPROX_LIVE_CLIENT_SECRET` as a global, so this run's phase 4 chose **E mode**
and its vault seed passed the (identical, already-held) real value as a
`--value` argument — transient local argv exposure, formalised as the finding
above (az's log redaction verified: nothing on disk). Two fixes: the fallback
now uses locals so the mode is not leaked (`96ff938`), and the E-mode seed
itself moved to the `--file <(printf '%s' …)` pipe channel, so no argv path
carries the real secret even in E mode. **Post-fix re-run (2026-11-04, same
'go cycle' scope, V mode):** battery `1 2 4` all PASS — `P4 mode=V` vault-only
start → 200; wrong overwrite → restart → 502 `application/problem+json`, echo
check scoped to the shape (V mode holds no value); version-pipe restore →
restart → 200; P1/P2 green again with the vault-fetch fallback and no exported
env. The battery now never holds the value at all in this configuration.

Survivors after the cycle: RG `credprox-live-test`; `credprox-e5-oauth` (1
credential, expires 2026-12-04, its SP with Reader on the RG);
`credprox-live-kv` (1 secret, 1 version, Secrets Officer role assignment).
One-command apply / one-command destroy bar **met**, including through two
real-world failure-and-repair rounds.

## Adversarial pass (2026-11-04, M9-style, pre-close)

Scope per the M26 row: the battery scripts' handling of secret material and
the scrub assertions against REAL failure bodies; the forged-token variants
were Phase 3's and are **out of scope** (phase dropped 2026-11-03,
OBO removed in M27). Findings and dispositions:

1. **E-mode `--value` argv exposure** — found in the pre-execution review,
   fixed at `da54c97`, disclosed in full above. No further exposure found on
   re-read of every az/dotnet/env invocation in the five scripts.
2. **Scratch-hygiene claim was false** (this pass): the report header says
   scratch responses are "deleted after each run", but the battery had no
   cleanup — stale files (incl. `credprox-live-sub.json`, a real
   subscription list) sat in `/tmp` after the cycle runs. Fixed: the EXIT
   trap now removes all five scratch paths; proven live (leftovers from the
   13:5xZ run cleared on a no-op invocation).
3. **Crash window in overwrite rotation** (this pass): a run dying between
   the wrong-value overwrite and the version-pipe restore leaves the vault's
   CURRENT version wrong — recovery without the battery is promoting the
   previous version (still in vault history) through the same `--file` pipe;
   documented as a comment at the overwrite step.
4. **`env NAME=$SECRET` proxy handoff** — inherent transient-argv channel for
   the dashed config key; disclosed above, no code change (dotted keys cannot
   be exported; the file-based alternative would put the value on disk,
   strictly worse).
5. **Teardown coverage read for the survivor list**: deleting the RG
   soft-deletes but does NOT purge the vault (purge protection off by
   omission); the full clean-state path is `live-e5-app.sh destroy` +
   `live-infra-destroy.sh` (purge + read-back), with
   `teardown-live-test.sh` remaining the coarse net by exact name.
6. **Scrub assertions against real bodies**: P2 greps the REAL 401→502
   caller body for the value's prefix (battery holds it in that run class);
   P4 V mode honestly scopes its claim to the `problem+json` shape — no
   fake-object substitutions. Confirmed against live outputs.

Verdict: the battery's secret-handling paths are clean after 2 and 3's
script fixes; no `src/` delta. No secrets in the tree — re-checked: the only
literal secret-shaped string in the scripts is the fixed dummy.

## Round 2 (M29) — Azure as the host: managed identity + vault-sourced credentials (2026-11-06)

Maintainer go-ahead 2026-11-05 ("merge, start M29, hold release") plus the scope
correction "use AME azure regions" → eastus. Phase definitions, pass criteria
and the corrected P10 semantics live in
`docs/azure-live-test-plan.md` (round-2 section); this section records the
runs and what the live layer actually taught. Zero `src/` delta: every fix
11–17 landed in sample code, scripts and docs only.

### Runs

- **Pre-ruling pass (2026-11-06):** revision `--0000004` (build
  `574740afd7b4`) — P5–P9 PASS on direct battery logs; P10 stopped honest:
  the wrong key was never refused because the then-59-min stub token left no
  mint inside the witness window. This produced ruling B+C
  (2-minute stub + next-mint semantics, below).
- **Main pass (2026-11-06, fixes 11–15):** revision `--0000005`, image stamp
  `DEPLOY_IMAGE_DIGEST=sha256:e9c65308de74…` — **P5–P10 PASS** on direct
  battery logs. Same-tag re-push needs the digest stamp + revision bump; the
  stamp is the only freshness witness on Container Apps.
- **Recreate cycle (step 9):** material destroy→create and infra
  destroy→apply, then P5–P10 **PASS again** on the same stamped digest —
  one-command apply/destroy proven for the round-2 objects too.
- **P10 detail (2-minute stub, stated plainly):** the live deployment set
  `CredProxTest__stub-token-minutes=2` on the counterparty for the witness;
  the **code default remains 59** and no shipped behaviour changed. Refusal
  observed ≈82 s after the wrong-key overwrite vs the ≈90 s prediction
  (120 s lifetime × 0.8 `RefreshFraction`); original key restored 18:43:21Z
  (`secret download`, never `show -o tsv`); recovery on the next probe 33 s
  later; vault ends provably ORIGINAL and the job args back to the 4-phase
  form.

### Round-2 live findings

1. **Mint cadence dominates reload.** A rotated `secret:` value is read live
   per assertion MINT, but mints only happen when the exchanged access token
   refreshes: staleness bound = token lifetime × `RefreshFraction` (0.8), NOT
   the config `ReloadInterval`. Live proof: a wrong key held 6.5 min against
   the 59-min stub was never refused. Ruling B+C adopted: short stub live,
   documented next-mint semantics (plan 455–500 corrected the same day).
2. **ACR pull identity on Container Apps:** the environment-level identity
   does NOT pull; the identity must be attached (`identity assign`) **and
   selected** via `configuration.registries[].identity`. App side proven
   first, then the battery job — both use this mechanism now.
3. **Two user-assigned identities on one Container App:** `ClientSecret`
   flows pick the identity by `ManagedIdentityClientId` **in code**; an
   env-level hint never reaches the ACA managed-identity wire.
4. **Vault-pinned CA for mTLS:** the counterparty's pinned client
   CA travels from the vault into the app's custom trust store
   (`ExtraStore` → `CustomRootTrust`); the OS store never has it on ACA.
5. **`az rest` leading-dash values:** container-app job `args`
   starting with `--` must be passed as `--args=NAME=VALUE`.
6. **Accepted-empty job start:** a start call returning no execution
   name yet leaving a run queued is **LAUNCHED** — never blindly restart;
   stderr carries the diagnostics.
7. **Decorated ACA logs:** `job logs show` lines carry a
   timestamp/level decoration; the battery strips it, wants 4 of 6 phase
   lines, and retries the log-store 409 window.
8. **Env-key normalisation (silent, cost two debug layers):**
   `AddEnvironmentVariables` maps `__` in names to the config `:` separator —
   `KeyVault__Uri` is only reachable as `KeyVault:Uri`; a raw-name lookup
   returns null silently and looked like "vault provider missing".
9. **ARM async deletes land 2–4 min late (fixes 16/17):** destroy scripts now
   poll read-backs (4-min cap for registry-class resources) and **fail their
   own exit code** when leftovers survive — one teardown honestly FAILed at
   the 3-min mark and passed when given the true window. A script that exits
   0 regardless makes the caller's OK marker a lie.
10. **Battery timestamp anchor:** the round-2 smoke logs carried no
    timestamps, so refusal/recovery windows could only be timed from Azure
    execution metadata. The battery now prints one anchor line
    (`battery UTC <iso> phase <p> build <digest|unstamped>`); every P-line
    inherits it in future runs.

### What round 2 did NOT prove

- net8.0 runtime behaviour — moot: the library ships for net10.0 only (.NET 8 was
  dropped at the M5 gate).
- Live rotation of the counterparty-pinned key pair — the pin is static for
  P10 by design (ruling B+C); delete+re-add rotation was deliberately not
  tested (rotate-by-overwrite is the rule under test).
- Reload firing without restart is proven **offline only**
  (`--mode reloadproof`); P10 carries the live next-mint timing witness.
- Throttling / idempotency scope — excluded by the maintainer ("skip rate
  limiting").
- Security-milestone adversarial pass: **scheduled**, not yet run.

Tenant after the run: resource group `exists=false`, both vaults soft-deleted
and **purged** (`az keyvault list-deleted` → 0), 0 role assignments — verified
by read-backs the destroy script failed its own exit over.

## Pending

- **Phase 3 — DROPPED 2026-11-03, OBO removed in M27.** The
  device-code sign-in never ran; the `credprox-e14-*` app registrations,
  their service principals and the local scratch then in hand were deleted
  and verified the same day (amended 2026-11-04, review F1: that day's
  deletion did **not** cover the manual wiring-window files — `credprox-m4-*`,
  `credprox-pc-body.json`, `credprox-devicecode.log` — which persisted until
  2026-11-04 and were deleted then with read-back; the battery's EXIT trap
  only ever covered `/tmp/credprox-live-*`, and teardown's scratch net was
  generalized to all `/tmp/credprox-*` in `8197365`). The library's OBO grant
  carries only fake-level unit coverage until M27 removes it. Wiring findings
  are preserved above.
- Phase 4 (Key Vault secret source): **executed 2026-11-04 — see the Runs
  section above.** The full history (03:02Z go-ahead → STOP on the secret-availability
  precondition → maintainer option (b) → V-mode PASS) is recorded in the
  milestone's execution log.
  Wiring behind it: the E5 sample wires the Key Vault config provider behind
  `KeyVault:Uri` (package `Azure.Extensions.AspNetCore.Configuration.Secrets`
  pinned 1.3.2 — 1.5+ drags Azure.Core 1.61 whose credential merge collides
  CS0433 with the repo-pinned Azure.Identity 1.13.1); battery `phase4()` runs the
  overwrite-rotation probe in E or V mode, maintainer-present-gated.
