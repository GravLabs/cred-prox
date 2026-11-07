# Live Azure/Entra validation plan (M26 + M29 round 2)

**What this document is:** the test plan behind the live Azure/Entra validation
milestones — what was tested, against what, and under which safety gates. It is a
test record, not user guidance.

Status: adopted — milestone row in §7 (approved 2026-10-30). Phase 3
was **dropped 2026-11-03** (Entra OBO removed from CredProx;
M27 owns the removal); Phases 1, 2, 4 and 5 **executed PASS 2026-11-04** —
evidence in `docs/live-validation-report.md`; the Phase 5 cycle destroyed and
rebuilt every object (survivors at the time: `credprox-e5-oauth` and
`credprox-live-kv` in `credprox-live-test`). Those survivors were deleted in
the authorized full teardown after M26 closed; read-back 2026-11-05
(read-only az): RG `credprox-live-test` absent, vault absent — round 2 starts
from clean slate. **Round 2 (M29) below: phases + pass criteria written BEFORE
code; the round-2 direction was approved 2026-11-04/05; NO tenant mutation
happens until one maintainer go-ahead over the gate list.**
The binding terms for this milestone: strictly the consent-free
set (Graph admin-consent variants parked in the §8.6 backlog), M9-style
adversarial pass before close, teardown before any creation, maintainer present
for every tenant mutation, and the battery runs locally — not in CI secrets.
Decision inputs: the maintainer chose the **production tenant** (2026-10-30) and
authorized the internal-repository sync; the GitHub launch is done (CI green).

## Why

Every Microsoft/Entra/Azure path in CredProx is currently proven only against
fakes and local stubs: `FakeTokenCredential` in the unit tests, Keycloak for
M14 inbound validation, in-process stubs downstream. The plan's own quality bar
(§5.1 line "Live vendor smoke", §6 E5 row) already names a real Entra tenant +
app registration as the intended proof — this plan makes that proof exist, on
the maintainer's subscription, and closes the biggest fidelity gap in the test
story.

What is NOT in scope: E4 Spotify and E6 ADP live vendor smokes (no vendor
accounts; unchanged build-only status), and any change to published behaviour.
Expected code delta in `src/`: zero — this validates what is shipped.

## Ground rules (all phases)

- **One blast radius**: every Azure resource lives in a single tagged resource
  group `credprox-live-test`; every Entra object is named `credprox-*`. A
  teardown script deletes everything. Nothing existing in the tenant or
  subscription is touched, modified, or depended on.
- **Minimum permission, consent-free by default**: prefer Azure RBAC
  (Reader on a test resource group / the vault) over Graph app permissions —
  Graph `*.All` application permissions need admin consent, which may be
  blocked in a prod tenant. The default design needs no admin consent beyond
  the maintainer's own account. (If self-consent is possible, the Graph-scoped
  variants below are optional add-ons.)
- **Secret hygiene unchanged**: no real secret is ever committed
  (`samples/ADP/appsettings.RealAdp.json` header rule, SECURITY.md). Real
  values live in environment variables or user-secrets on the dev machine only.
- **Local execution, not CI**: the GitHub repo is public and this is a
  production tenant — pushing a real service-principal secret into repository
  secrets hands a public-repo runner a credential into the tenant. Real-tenant
  smokes run **here** (`az login` as the maintainer), manually or on a local
  timer. The §9 "nightly needs repo secrets" line stays a documented option,
  deliberately unused for the tenant paths. A future dedicated low-privilege
  SP + conditional access could revisit this; not now.

## Phase 1 — Secretless managed identity against real Azure (lowest friction)

Exercises: `AddCredProxAzureTokenCredential(DefaultAzureCredential)` — the
exact type `CredProx.AzureKeyVault` ships — getting a **real Entra token for a
real Azure REST call**, no secret anywhere.

1. `az group create -n credprox-live-test -l <region>`
2. `az identity create -n credprox-uai -g credprox-live-test`
3. RBAC: Reader on that resource group for the UAI.
4. Run E5 MicrosoftGraph `--variant identity` with env overrides: token scope
   `https://management.azure.com/.default`, destination `management.azure.com`,
   then `GET …/subscriptions?api-version=2022-12-01` through the proxy →
   expect 200 and a subscription list; expect `401`/rejected on a forged or
   expired inbound token (the sample's own caller path).
5. Cache proof: two proxied calls within the token lifetime hit the ARM token
   endpoint once (log/assert on the provider's single-flight — mirrors
   `AzureTokenCredentialProviderTests` but with the real credential chain).

Config-only via `CredProx__…` env overrides if the existing keys bind
(fix during the slice if any key resists env override — that itself is a
finding worth shipping).

**Pass =** real 200 from ARM through CredProx with zero client secrets.

## Phase 2 — Entra client-credentials variant (the classic secret path)

1. App registration `credprox-e5-oauth` in the prod tenant; client secret;
   RBAC Reader on `credprox-live-test` for its service principal (again
   consent-free, targeting ARM). Optional add-on if consent is available:
   Graph `User.Read.All` (application) + `graph/.default` against
   `graph.microsoft.com` as the appsettings default already assumes.
2. Run E5's OAuth variant: CredProx mints a real `…/oauth2/v2.0/token`
   client-credentials token, caches it, and a second request reuses it;
   wrong-secret config produces the scrubbed failure (no secret echo — the
   M20 scrubbing guarantee proven against a live IdP, not a WireMock echo).

**Pass =** real token minted + cached + used; secret never appears in any log
or error output (assert scrub side-by-side, vendor-side raw vs caller-side
`[redacted]` per the post-M20 smoke discipline).

## Phase 3 — Entra as the real M14 issuer: inbound validation + OBO exchange

**Status (2026-11-03): dropped, OBO removed in M27 — this phase
never ran.** The `credprox-e14-*` app registrations and their service
principals were deleted 2026-11-03 on the maintainer's go-ahead; the device-code
sign-in was never performed. The tenant-environment findings the wiring
attempt did surface are preserved in `docs/live-validation-report.md`.
Prose below kept as history.

The library's Entra OBO grant (`TokenExchangeProvider.cs`, the
`urn:ietf:params:oauth:grant-type:jwt-bearer` path) has **no sample coverage
at all today** — Keycloak proves RFC 8693, Entra's OBO specifics (audience,
`kid` rotation, issuer aliasing) are unproven. This is the highest-value
phase.

1. App registration `credprox-e14-api`: the protected downstream audience.
   App registration `credprox-e14-client`: public client (device code flow
   enabled), delegated `User.Read` (user-consented — no admin consent).
2. Device-code sign-in as the maintainer → a **real Entra-issued inbound token**.
3. Run E14 pointed at Entra authority (`Authority` mode → real OIDC metadata
   + JWKS fetch, real `kid` rotation cache path):
   - real inbound token → accepted, OBO exchange to a second real resource
     (target scope pinned during the slice — candidates:
     `https://vault.azure.net/user_impersonation`, which also chains into
     Phase 4, or Graph delegated);
   - token from a different tenant / wrong `aud` / expired → 401
     `InboundTokenRejectedException` before any exchange call;
   - caller key still enforced; downstream refuses the inbound token (audience
     separation) — the E14 invariants, against the real IdP.

**Pass =** real Entra token accepted with correct claims; every forged variant
rejected; exchanged token valid at the real target API.

## Phase 4 — Azure Key Vault as a real secret source

The E5 `Program.cs:59` Key-Vault config-provider line is commented in the
sample and has never run against a real vault.

1. `credprox-live-kv` vault (RBAC auth model, maintainer + UAI get
   *Key Vault Secrets User* on the vault or the single secret).
2. Store `CredProx--Secrets--graph-client-secret` (the Phase 2 secret) in the
   vault; run E5 with the vault provider enabled — proving the documented
   production shape: **client secret material enters the process only from a
   real vault**. Rotation is by overwrite; an overwritten value reaches a
   RUNNING process only when the provider is polling - `ReloadInterval` set
   explicitly (the vendor default never polls; the samples set 30s) - else on
   a restart. Nothing on disk.

**Pass =** E5 starts and brokers a live token with the secret supplied solely
by the vault; rotation is proven by **overwrite** — wrong value → clean
failure → correct value → recovery (gate scope set
2026-11-03). NOT delete+re-add: the vault's soft-delete name lock makes a
same-name re-add impossible short of purge, and a genuinely new value would
need its own e5-oauth credential reset — a separate tenant mutation.

## Phase 5 — Repeatable infrastructure: Bicep + paired Entra app lifecycle

Design decision **2026-10-31** (first written here 2026-11-04): **Bicep**
chosen over Terraform (Azure-native), and the Entra app registration kept
**outside** Bicep as a paired script (app registrations are tenant-wide, not
RG-scoped). The live smoke battery and teardown script from the original
Phase 5 text shipped with Phases 1/2/4.

- `infra/azure/credprox-live.bicep` — the RG-scoped contents: `credprox-live-kv`
  (RBAC authorization model; `northeurope` because this tenant's location policy
  rejects the RG's home region for vaults — finding 1) plus the maintainer's **Key
  Vault Secrets Officer** role assignment. One parameter: the officer principal
  id — apply resolves the signed-in az identity, so no GUID is baked in the
  tree.
- `scripts/live-infra-apply.sh` / `scripts/live-infra-destroy.sh` — one command
  each. **KV soft-delete decision:** destroy **deletes and purges** (purge
  protection stays off) — a deterministic clean slate; plain `recover` would
  silently resurrect stale secret history, which is wrong for a destroy/apply
  cycle. If destroy is interrupted mid-way, apply still recovers a
  soft-deleted vault before deploying (same-name create is name-locked).
  `softDeleteRetentionInDays` cannot be changed on an existing vault, so the
  template's 90→7 only takes effect on a **fresh create** — exactly what the
  purge path gives you; destroy's read-back reports which state was actually
  left (purged vs soft-deleted), and the cycle's evidence records which
  re-apply path was taken.
- `scripts/live-e5-app.sh create|destroy` — the paired Entra lifecycle: `create`
  registers the app, creates its service principal (not auto-provisioned in
  this tenant — finding 4), grants Reader on the RG, and pipes a fresh 30-day
  credential **straight into the vault** — the M26 Phase 4 pipe: value never
  printed, never in argv, never on disk. `destroy` deletes the RG Reader
  grant **first** (a deleted SP would otherwise orphan it as an 'Unknown'
  principal), then SP + app
  (idempotent).
- **Bar:** one-command apply + one-command destroy, **proven by a
  destroy → apply → re-run (battery 1/2/4) cycle**. To keep the re-run one
  command, battery phase 2 gains a vault-fetch fallback: after a recreate the
  secret exists only in the vault, so the battery pulls it through the az CLI
  identity into its own environment (same exposure as the maintainer-exported env —
  never printed, never on disk), then runs the existing checks unchanged.
- Offline validation (no tenant mutation): `az bicep build` compile +
  `az deployment group what-if` (read-only). The live destroy→apply→re-run
  cycle is a tenant mutation set: **go-ahead gated, maintainer present**, exact
  command list handed over before execution.

## Costs, risks, cleanup

- **Cost**: managed identities free; one vault ≈ pennies; RG empty of billable
  compute → effectively zero. **Cleanup**: one RG + three named app registrations
  + one vault, all `credprox-*`-named and deletable; teardown script included.
- **Risk**: the only genuinely new tenant exposure is three app registrations
  and two RBAC assignments; all reversible, none touching existing tenants,
  subscriptions beyond RBAC on a new RG, or billing.
- **What this can catch that fakes cannot**: Entra issuer-aliasing/audience
  mismatches in M14 validation, OBO grant shape Entra actually accepts
  (dropped with OBO in M27),
  `DefaultAzureCredential` chain behaviour under CredProx's timeout/cancel
  paths, vault-latency vs cache single-flight, and any place our scrubbing
  over- or under-redacts a *real* `RequestFailedException` body.

## Sequencing and sizing

One slice (proposed **M26**), one branch. Order = 1 → 2 → 3 → 4 → 5 (Phase 3
later dropped — see its status); each
phase is independently valuable and independently shippable (the battery
script only wraps what passed). Phase 1 is the cheapest proof and can be
first-run within the same sitting as setup. M9-style adversarial pass applies
(secret handling + JWT paths are in scope). Review gates per usual §5.3 +
fresh-obj pack per ADR-0001's note.

---

# Round 2 (M29) — CredProx running **in** Azure: managed identity + Key Vault keys/certs

The round-2 direction was approved 2026-11-04/05; release held; **every
tenant mutation below is gated on one maintainer go-ahead over the gate list**
(§"Maintainer gate list" at the end). Read-only az calls (lookups, what-if) are
what this section was written from — 2026-11-05.

## R2 · Why

Round 1 proved CredProx **against** Azure (local process, maintainer's `az login`
token). Two things were never exercised: (1) CredProx running **inside** Azure
on a **real user-assigned managed identity** (round 1 created `credprox-uai`
but never used it as an identity — report:165 "no test UAI exists" pre-dated
it; the battery always used the maintainer's sign-in or a client secret), and
(2) Key Vault as the source of **signing keys and client certificates** —
round 1's vault carried one opaque client secret only.

## R2 · Capability ground truth (src-verified at `92c4a58`, zero src delta)

All facts below were opened and read by the builder 2026-11-05; a reviewer can
re-check every line:

| Ask | Works from vault today? | Proof (src/CredProx) |
|---|---|---|
| `secret:` is the only scheme; KV feeds it via stock config provider | yes (by design) | `Secrets/SecretReferences.cs:17`; `Secrets/ConfigurationSecretSource.cs` (only `ISecretSource`; doc comment: KV plugs in as a configuration provider); host-side shape already shipped: `samples/MicrosoftGraph/Program.cs:45` `AddAzureKeyVault(uri, DefaultAzureCredential())` + `:81` `AddCredProxConfigurationSecrets` — vault secret `CredProx--Secrets--<name>` answers `secret:<name>` |
| JWT assertion signing **key** (PEM) | yes | `Credentials/JwtAssertionProvider.cs:190` `SigningKey` → `SecretValues.ResolveIfReferenceAsync`; `:324/:331` `ImportFromPem` (real newlines required — nothing in the path encodes/truncates them) |
| JWT assertion signing **cert** (PFX) | yes, **passwordless** base64 PKCS#12 only | `JwtAssertionProvider.cs:192-193, 335-339` |
| HMAC credential secret | yes | `Credentials/HmacProvider.cs:17` Type `"Hmac"`, `:36-37` resolves `secret:`; DI `DependencyInjection/CredProxServiceCollectionExtensions.cs:158` |
| mTLS client certificate (PEM bundle **or** base64 PFX, encrypted supported) | yes | `Connections/ClientCertificateLoader.cs:32-34,57-60`; `ClientCertificatePassword` read as ref too — exercises the password path the JWT type lacks |
| Inbound caller key | inline config only (not vault-able) | `CallerKeysOptions` — honest caveat: the inbound edge key is a config string; acceptable for the test (it guards the internal edge), noted as a finding, **not changed** (src delta stays zero) |
| Vault byte fidelity for multi-line PEM | **UNVERIFIED:** — `Azure.Extensions.AspNetCore.Configuration.Secrets` is outside this repo; confirm against vendor docs | provider JSON-parses only JSON content-types (documented behaviour; confirm) |

So the row's expectation holds: **zero `src/` delta**. No new design is needed
— the test proves the shipped design on material it has never carried.

## R2 · Design answers (the four contract points)

- **Ingress = default-deny.** The Container App is created with **external
  ingress disabled** — zero public listener, no IP allow-list to rot. The
  battery reaches it as a **Manual Container Apps Job** (`credprox-m29-battery`
  — same image, same UAI) in the same environment, calling the app's **internal
  ingress FQDN**. The original `az containerapp exec` transport was replaced
  for unattended reliability: az's own help calls it an "SSH-like interactive shell", it
  needs a TTY, and no offline gate could catch it failing unattended. Zero
  public listeners either way. Fallback, documented but **not
  default**: external ingress + IP restriction to the maintainer's egress IP +
  caller key on every route. (Caller keys are on regardless — defense in
  depth, and it keeps the P7 negative test meaningful.)
- **Consent-free.** Round 2 creates **no app registrations, no Graph API
  permissions, no credential resets**. All authorization is Azure RBAC,
  self-serviceable at single-resource scope: UAI ← **Key Vault Secrets User**
  on the vault only; environment's system identity ← **AcrPull** on the ACR
  only; maintainer ← **Key Vault Secrets Officer** on the vault only. The ARM egress
  probe (`GET /subscriptions`) needs no role at all (round 1 Phase 1 held this
  property; it held for a user token — the UAI variant is re-proven, honestly).
- **Counterparties — what proves what, without overclaim.** The vault→
  credential→wire correctness is proven by verifiers **we run** inside the app
  (same bar as the shipped `GitHubApp --smoke` stub, `HmacSigning` verifier and
  `NginxMTls` E2E): signature **correctness**, not vendor trust.
  - JWT: counterparty cryptographically verifies the `client_assertion`
    (RS256) against the pinned public key + checks `aud`, mirrors
    `samples/GitHubApp/Program.cs:59,114`.
  - HMAC: counterparty independently recomputes
    `METHOD \n PATH \n unix-seconds \n sha256(body)` (HmacSigning shape,
    `samples/HmacSigning/Program.cs:27-48`).
  - mTLS: counterparty terminates TLS with **client-cert required**, pinned to
    the test CA, echoes the client DN — a 200 + `CN=credprox-m29-client` proves
    CredProx loaded the vault PFX (+password) and presented it and the chain
    verified.
  - **Not claimed:** Keycloak never verifies a client assertion (no
    `private_key_jwt` realm in the repo); WireMock does no crypto; the vendor
    side (GitHub) is out of scope (no live vendor creds); the vault **custodies
    and delivers** key material — it does **not** perform crypto operations
    (no HSM-signing claim; KV crypto API is out of scope with zero src delta).
  - Test-only PKI: self-signed CA generated in the material script; trust =
    pinning, exactly as the E2E mTLS tests do.
- **Region.** Decided 2026-11-06: **Americas regions only**. Live read-only
  what-if 2026-11-06:
  `eastus`, `eastus2`, `centralus`, `westus2`, `southcentralus`,
  `canadacentral` all clean (9 creates each); `westeurope` re-probed as the
  negative control and still rejected (`RequestDisallowedByAzure`) — the probe
  is live, not recollection. The tenant location policy (`denyLocation`)
  remains unreadable from the maintainer account (management-group read →
  AuthorizationFailed), and **RG-create** policy remains the one thing what-if
  does not evaluate.
  **Default: `eastus` — main AND vault.** If RG create or any region step is
  refused: next `eastus2`, `centralus`, `westus2`, `southcentralus`,
  `canadacentral` — retry that step **same region for both**. No non-Americas
  region anywhere, including the round-1 `northeurope`: the vault's old Key
  Vault RP exemption there is moot (the 2026-11-06 Americas what-if never
  flagged the vault), so the vault follows the chosen location everywhere and
  destroy purges it with the same value (`-l`). Scripts take the region as
  arg 1 (apply and destroy alike); no GUID or region baked into the tree.

## R2 · Phases and pass criteria

Each live phase = one maintainer go-ahead. "Offline" steps were executed while
preparing this row (see evidence line in each). Resource names: RG
`credprox-live-test` (same single blast radius), vault `credprox-m29-kv`, UAI
`credprox-m29-uai`, ACR `credproxm29reg`, env `credprox-m29-env`, app
`credprox-m29-app`, sample `samples/AzureContainerApps`, all Entra-side names
`credprox-*` — none exist today (clean slate re-verified read-only 2026-11-05).

### R2.1 — Infrastructure (Bicep) [live: apply]
`infra/azure/credprox-live-r2.bicep`: RG-scoped — UAI; vault (RBAC model,
soft-delete 7, **purge protection omitted**, region = `vaultLocation`
parameter, passed same-region by apply since the 2026-11-06 decision); ACR Basic;
Container Apps environment (Consumption); the three single-scope RBAC
assignments (role ids resolved live, never in the tree — M26 Phase-5 rule).
The Container **App** itself ships via `az containerapp` CLI (its template is
CLI ergonomics-heavy; decision recorded, Bicep carries everything else).
Offline gates: `az bicep build` with **zero BCP diagnostics** — clean means
zero WARNINGS too, not just no errors (live lesson 2026-11-06: a BCP037
warning on a property the RP does not have was the offline signal that the
live deployment later proved: the ARM deployment 400'd and the property read
back null); **subscription-scope what-if** clean
via the `credprox-live-r2-sub.bicep` wrapper (a group-scoped what-if would
first need the RG — a mutation; the sub wrapper validates the same resource
set without it, and proved to also evaluate the tenant location policy at
resource level — see §Region).
Pass (live, az read-back): vault `enableRbacAuthorization: true`,
`enablePurgeProtection: null`, retention 7; vault-scope role list **exactly
the declared set**; ACR SKU Basic; env `provisioningState: Succeeded`.

### R2.2 — Vault material [live: data-plane writes]
`scripts/live-m29-material.sh create|destroy` (vault data plane; go-ahead-gated):
JWT RSA-2048 key PEM → `CredProx--Secrets--jwt-signing-key`, public part →
`CredProxTest--jwt-public`; HMAC key (32-byte base64) →
`CredProx--Secrets--hmac-key`; self-signed client cert (CN
`credprox-m29-client`) as **password-encrypted** PKCS#12 →
`CredProx--Secrets--mtls-client-cert` + `…--mtls-client-cert-password`; test CA
cert (public) → `CredProxTest--mtls-ca` **and** its base64 single-line form
`CredProxTest--mtls-ca-b64` (the trust anchor the proxy container consumes via env
→ `update-ca-certificates` — PUBLIC material, so env carriage is deliberate;
secrets stay vault-only); inbound caller key →
`CredProx--Secrets--caller-key` plus its **public half** `sha256:<hex>` →
`CredProxTest--caller-key-hash` (the caller registry is inline config and needs
the hash, not the key — ground-truth table above); counterparty **server**
cert (CA-signed, CN `credprox-m29-counterparty`, SAN
`DNS:localhost,IP:127.0.0.1`, serverAuth) as **password-encrypted** PFX →
`CredProx--Secrets--cp-server-cert` + `…--cp-server-cert-password` — the mTLS
listener's own identity, vault-carried like the rest. **Eleven** names.
**Byte hygiene:** every single-line secret is stored WITHOUT a trailing
newline (`tr -d '\n'`) so the stored bytes equal exactly what the PFX loader /
the caller-key header / the hash comparison sees; PEMs keep real newlines.
Values generated locally, piped
(`--file <(printf …)` pattern — never argv, never disk, never printed; M26
Phase-4 discipline). Destroy = delete all versions; the vault purge in
infrastructure destroy covers everything (teardown matrix below).
Pass: read-back lists **exactly these eleven secret names**, one version each;
evidence shows names only.

**Namespace rule (amended 2026-11-06 after the first live delivery):** public
wiring material uses the `CredProxTest--` prefix. `CredProx--<path>` becomes
config key `CredProx:<path>`; the shipped config validator refuses any key it
cannot bind under `CredProx` at proxy startup, while the vault provider feeds
every vault secret into every host's configuration — so foreign material under
`CredProx--` crashes the proxy (observed: `CrashLoopBackOff` on
`caller-key-hash`/`jwt-public`/`mtls-ca*`). Only bindable product option paths
may use the `CredProx--` namespace.

### R2.3 — Host sample, image, deploy [live: push + create]
`samples/AzureContainerApps` — **built (G1, 3383e61)**: one image, three
modes: `--mode proxy`
(Operations-shaped minimal CredProx host + MicrosoftGraph-shaped KV/MI wiring:
`AddAzureKeyVault` + `AddCredProxConfigurationSecrets` +
`AddCredProxAzureTokenCredential(DefaultAzureCredential())`, **config re-add
order** per `samples/MicrosoftGraph/Program.cs:30-34` — the M26 Phase-1 trap),
`--mode counterparty` (three verifiers above; TLS listener requires the client
cert and takes its OWN identity from the vault server-cert secrets) and
`--mode battery` (the R2.4 probes; machine-readable `P<n> PASS/FAIL` lines +
`BATTERY OK/FAILED`). Routes: `/arm/*` →
`management.azure.com` (Type `TokenCredential` — the UAI path), `/jwt/*` →
counterparty (JwtAssertion, `SigningKey: secret:jwt-signing-key`), `/hmac/*` →
counterparty (Hmac, `Secret: secret:hmac-key`), `/mtls/*` → counterparty TLS
(`CredProx.Connection: mtls` on the CLUSTER — route-level placement starts the
connection clean but never attaches the cert — plus `ClientCertificate:
secret:mtls-client-cert` + password). The counterparty namespaces its
endpoints (`/jwt/echo`…), so ONLY `/arm` strips its prefix.
Config carries **only the vault URI** (plus the caller-key HASH and the CA
PUBLIC material — never secret values) — no secret material in env or config
files (that IS the test). ACA app: two containers (proxy with internal-only
ingress :8081, counterparty localhost-only), identity = the UAI.
`scripts/live-m29-deploy-app.sh` (go-ahead-gated step): ACR login, `docker build`
locally (Docker available) → push as `credprox-m29:latest`, app create/update,
**read back** the internal FQDN (`containerapp show` — never guessed), then
create/update the battery job against that FQDN. The G1 **offline gate
already ran**: `docker build` + `--mode proxy --smoke` (generated material,
local stub ARM endpoint + local counterparty, no vault/Azure) —
`P5 PASS … P9 PASS` + `SMOKE OK` green 2026-11-05. The smoke earned its slot:
it caught four wiring bugs host-build-green missed (destination `Template` is
the authoritative egress prefix; `CredProx.Connection` is CLUSTER metadata;
prefix-strip vs the namespaced counterparty; `TokenCredential` DI ordering).
Live Pass: app **and job** `provisioningState: Succeeded`, app running;
battery run per R2.4.

### R2.4 — Battery as a Manual Container Apps Job [live: read-only inside]
Transport (G2): **`credprox-m29-battery`**, a Manual Container Apps **Job** in
the same environment — same image, same UAI, template
`infra/azure/aca-job-r2.yaml.tmpl`, `replicaTimeout 900`. Mechanics in
`scripts/live-azure-smoke.sh`: `az containerapp job start` → poll `job
execution show` to a terminal status (≤60×8 s — cold start + pull on
Consumption can outlast 320 s) → `job logs show --container battery --tail
300`; the battery's `P<n> PASS/FAIL` lines are the evidence, and a `Failed`
execution is a **result to parse**, not an infra error. **One shared
`--phase all` run feeds P5–P9** (latched: one dead job fails them all without
re-starting it). P10 retargets the job args to single-probe `--phase jwtprobe`
runs and restores them on every path. Placement judgment: the job is
deliberately NOT in the Bicep — like the app itself it lives beside the
environment in the gated deploy script, and it joins the teardown matrix +
gate list (what G2 required). **UNVERIFIED:** whether the job's image pull
succeeds with the kubelet identity attached AND selected via
`configuration.registries[].identity` — the mechanism both workloads now use
after the 2026-11-06 live finding (environment-level identity does not pull;
the app side is proven first, then the job); this run's first job start
proves it.
Battery phases **5/6/7/8/9** (numbers continue after round 1's 1/2/4 in
`scripts/live-azure-smoke.sh`; each prints PASS/FAIL/SKIP evidence, names and
statuses only):
- **P5 (MI egress):** `/arm/*` → 200 — first real managed-identity CredProx
  egress ever.
- **P6 (JWT from vault):** `/jwt/*` → 200 **and** counterparty echo
  `assertion-verified` + `aud-ok` (vault PEM produced a valid RS256 assertion).
- **P7 (HMAC from vault):** `/hmac/*` → 200 **and** verifier echo (vault secret
  signs correctly).
- **P8 (mTLS from vault):** `/mtls/*` → 200 **and** DN echo
  `CN=credprox-m29-client` (vault PFX+password loaded, chain verified against
  pinned CA).
- **P9 (edge hygiene):** no caller key → 401 (in-cluster, battery run);
  **no-secret boot check:** the **DECLARED** container env names carry no
  credential variables (host-side `containerapp show` read-back — the
  exec-era in-container `env` grep died with G2; the evidence wording states
  exactly which half proves what) — secret material demonstrably arrives only
  from the vault.
- **P10 (rotation):** the **M26-P4 overwrite pattern** on `jwt-signing-key`,
  witnessed by job probes: baseline `jwtprobe` must be green first (else P10
  FAILs pointing at P6) → overwrite with a wrong-but-well-formed key, kept
  live **until refused** (≤6 jwtprobe executions, 20 s apart) → restore the
  original on **every** path (downloaded via `secret download`, never
  `show -o tsv` which would mangle PEM newlines) → recovery = probes until
  `P6 PASS` again (≤9). The counterparty pins `jwt-public` - a separate
  secret, not rotated during P10 - so the pin stays static for the phase and
  the refusal cannot self-heal. Crash-window recovery: if a dead run left the wrong
  key in the vault, `live-m29-material.sh create` reseeds and the phase
  re-runs. Proves the vault
  is the live source feeding the JWT credential (rotate-by-overwrite rule —
  never delete+re-add). Chosen over a new-key-propagation variant because a
  rotated key pair needs the verifier's pinned public key to rotate in the
  same window — a reload race that tests sample timing, not the library.
  **Cadence semantics (corrected by the live run, ruling B+C 2026-11-06):**
  the original text here claimed the proxy's 30s `ReloadInterval` "drives the
  first-refusal and recovery timings" — FALSE as an end-to-end bound. `secret:` values
  are read live per assertion MINT, but a MINT happens only when the proxy's EXCHANGED
  access token refreshes: staleness of rotated signing material is bounded by
  `token lifetime × TokenCacheOptions.RefreshFraction (0.8)`, not by the reload
  interval (live evidence: a wrong key held 6.5 min against the then-59-min stub token
  was never refused; a 30s-reloaded config simply had no mint to serve it). The witness
  is therefore correct-by-construction ONLY when the stub token is short: the live
  deployment sets `CredProxTest__stub-token-minutes = 2` on the counterparty (code
  default 59 unchanged; the report states the 2-minute stub). Honest bounds: refusal
  expected within ≈ reload(30s) + refresh(≤ lifetime×0.8 = 96s) + one probe (~75s)
  ≈ 5 min, recovery likewise after restore; the refusal is persistent (every subsequent
  mint re-signs with the vault's current key), so transient log-husk probes cannot mask
  it. P10 remains the **live reload-interval witness** in the sense it can actually
  prove: the running process adopts the rotated value at its next mint —
  `ReloadInterval = 30s` set explicitly (vendor default null = NEVER poll, the M29 F2
  finding) is what makes that adoption reflect the CURRENT vault value; the
  reload firing without restart is proven offline by `--mode reloadproof`; P10 carries
  the live next-mint timing.
SKIP semantics (CI parity): no az sign-in **or** no `containerapp` CLI
extension **or** app **or job** absent **or** vault material unseeded (the
battery reports the missing caller key) → the new phases print SKIP and exit
0, matching the existing battery's contract (script header :9-12). Proven
three ways offline 2026-11-05: unauthenticated `--all` exit 0; unauthenticated
phases 5–10 exit 0; signed-in host without the round-2 objects → six per-phase
SKIPs, exit 0.

### R2.5 — Destroy → apply → re-run (the M26 bar) [live]
One-command destroy (`scripts/live-infra-destroy-r2.sh`) covering **every**
round-2 object, in dependency order: app **and battery job** delete → env
delete → ACR delete → vault **delete + purge** (plain delete name-locks —
round-1 finding) → both identity deletes. The **RG survives** destroy on
purpose (deterministic empty container so apply re-runs without the gate
step-1 create); the gate list's final cleanup removes it explicitly (step
10). Then one-command apply rebuilds; battery re-runs unchanged → PASS. Pass
= the cycle + read-backs (purged vs soft-deleted stated honestly, as round 1
did; the job row included).

## R2 · Teardown matrix (what destroy removes)

| Object | Removed by | Read-back |
|---|---|---|
| ACA app + containers | destroy step 1 | `containerapp show` → not found |
| battery job `credprox-m29-battery` (+ its executions) | destroy step 1 (same script pass, before the env) | `az resource show --resource-type Microsoft.App/jobs` → not found |
| CA environment | destroy step 2 | `containerapp env show` → not found |
| ACR (images inside) | destroy step 3 | `acr show` → not found |
| Vault **incl. all secret versions + purge** | destroy step 4 | `keyvault show` not found **and** `list-deleted` empty (purged) |
| UAIs (`credprox-m29-uai` + `credprox-m29-kubelet`) | destroy step 5 | `identity list` → no `credprox-*` |
| RG (everything RG-scoped) | gate list step 10 (destroy deliberately keeps the RG — R2.5) | `group exists` → false |
| RBAC assignments (vault/ACR-scoped) | go with their scopes (vault purge / ACR delete) | role list empty at recreate |
| Entra app registrations | **none in round 2 — N/A** (no registrations created; UAI is an ARM resource in the RG, so the paired-Entra script round 1 needed does not apply; recorded against the row contract) | n/a |

## R2 · Costs (real numbers — G4, re-priced for the Americas deploy 2026-11-06)

Rates from the **Azure Retail Prices API**, **eastus** USD pay-as-you-go,
queried from this box 2026-11-06 (deployment region follows the maintainer's
Americas word; the earlier uksouth/northeurope figures are superseded — same
source re-queried, not copied):

| Meter | Rate |
|---|---|
| ACA Standard vCPU **active** | $0.000024 /second |
| ACA memory **active** | $0.000003 /GiB-second |
| ACA vCPU **idle** | $0.000003 /second |
| ACA memory **idle** | $0.000003 /GiB-second |
| ACA requests | $0.40 /million |
| ACR Basic registry unit | $0.1666 /day (≈ $5/month; + $0.10/GB-month storage) |
| Key Vault Standard operations | $0.03 /10K |

The vendor pricing pages (`azure.microsoft.com/en-us/pricing/details/…`)
confirm the structure as fetched 2026-11-05: the Consumption free grant of
**180,000 vCPU-seconds + 360,000 GiB-seconds + 2 million requests per
subscription per month**, the ACR Basic tier, and per-10K vault metering.
The eastus meter list carries an **Environment management-hour** meter at
$0.10/h that the plan's earlier figures did not count. Resolved against the
vendor's own billing doc (`learn.microsoft.com/en-us/azure/container-apps/billing`,
fetched 2026-11-06): Consumption-plan billing "consists of two types of
charges" — resource consumption and HTTP requests — and "You aren't billed
any plan management charges unless you use a Dedicated workload profile in
your environment." That meter is the Dedicated-plan management fee; neither
workload profiles nor the features the doc lists as charged regardless of
plan (private endpoints, planned maintenance) exist in this environment, so
it does not apply and the figures stand.

Arithmetic (both app containers combined ≤ 1 vCPU / 2 GiB — this deploy caps
at 0.75 vCPU / 1.5 GiB, the battery job adds a transient 0.25/0.5 GiB for
seconds at a time), before the monthly free grant:

- **One-day test then teardown (gate 1→10 in a day): < $3.** Worst shape
  24 h fully active: (0.000024 + 2×0.000003)/s × 86,400 s ≈ **$2.59**; ACR
  Basic a day = **$0.17**; vault ops are hundreds, not tens of thousands ≈
  cents; battery requests far inside the 2 M/month free grant.
- **Left running a month, one idle replica (minReplicas 1): ≈ $29/month** — idle
  (0.000003 + 2×0.000003)/s × 86,400 × 30.4 ≈ $24 + ACR $5.
- **Left running a month, continuously active: ≈ $84/month** ($79 + $5).
  So **left running ≈ $29–85/month** — material, not nothing. **Don't
  leave it running.**
- The destroy cycle (R2.5) means the expected steady-state is **zero**;
  the RG itself is never billable.

## R2 · Maintainer gate list (exact commands, run order — deliverable 4)

Executed **maintainer-present**, each line with the one maintainer go-ahead
relayed at run time. (Main+vault region `eastus` default + Americas fallback order per
§Region, decision 2026-11-06; local prereq: `az containerapp -h` succeeds
— the group ships built-in on this box's az 2.91.0 (verified offline
2026-11-05); an `az extension add --name containerapp` install is only needed
if a future az drops the group. No tenant mutation either way.)

| # | Command | Creates / mutates | Reversible by |
|---|---|---|---|
| 1 | `az group create -n credprox-live-test -l eastus` | empty RG (only remaining policy unknown is RG-scope; if refused, next `eastus2`, then `centralus`, `westus2`, `southcentralus`, `canadacentral` per §Region — same region for ALL later steps) | 10 |
| 2 | `scripts/live-infra-apply-r2.sh [eastus]` | UAI, vault (SAME region — vault is a parameter now), ACR, CA env, 3 scoped role assignments (Bicep `credprox-live-r2.bicep`) | 8 |
| 3 | `scripts/live-m29-material.sh create` | 11 vault secrets (test PKI incl. counterparty server cert; keys + hashes; values via `--file`, never argv/disk) | 7 (destroy); 8 (purge covers) |
| 4 | `docker build samples/AzureContainerApps …` + `az acr login` + `docker push` | 1 image repo in ACR (local build; ACR is the only mutation) | 8 |
| 5 | `scripts/live-m29-deploy-app.sh` | ACA app (2 containers, internal ingress, UAI) + battery job `credprox-m29-battery` (G2; same env/identity, Manual trigger) | 8 |
| 6 | `scripts/live-azure-smoke.sh 5 6 7 8 9 10` | job executions only (starts `credprox-m29-battery`, reads its logs; P10 temporarily overwrites one vault secret and restores it, retargets job args around the witnesses and restores them; the P10 witness rides the RUNNING proxy's 30s vault reload - `ReloadInterval` set by the sample, vendor default never polls) | — |
| 7 | `scripts/live-m29-material.sh destroy` | removes the 11 secrets | — (idempotent) |
| 8 | `scripts/live-infra-destroy-r2.sh [eastus]` (same region arg used at apply) | full destroy in dependency order — app AND job, then the environment, THEN ACR, then vault delete + **purge**, then identities; read-backs prove each gone | — (terminal) |
| 9 | (cycle proof) 2 → 3 → 4 → 5 → 6 → 7 → 8 again | same as 2-8 — the M26 bar | — |
| 10 | `az group delete -n credprox-live-test --yes --no-wait` | belt-and-braces RG removal | — |

Offline evidence already carried by this row (no tenant effect): `az bicep
build` clean, `az deployment group what-if` clean, `bash -n` all scripts,
battery SKIP proof unauthenticated (exit 0), library gates per-project.

## R2 · What this can prove that fakes cannot

Real IMDS-backed `DefaultAzureCredential` under ACA's env contract; a vault-
delivered **private key** and **encrypted PFX** surviving config, template
expansion and `PemEncoding`/`X509CertificateLoader` end to end; RBAC-scoped
identity egress with zero secrets on the box; rotation latency of a real vault
against CredProx's cache single-flight; and the whole surface with **no public
listener**.
