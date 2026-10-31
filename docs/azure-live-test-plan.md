# Live Azure/Entra validation plan (draft, proposed as M26)

Status: draft for the person (PM) + dev-architect. Not yet a milestone row.
Decision inputs: the person chose the **production tenant** (2026-10-30) and
authorized the Gitea sync; GitHub launch (`eec19753`, CI green) is done.

## Why

Every Microsoft/Entra/Azure path in CredProx is currently proven only against
fakes and local stubs: `FakeTokenCredential` in the unit tests, Keycloak for
M14 inbound validation, in-process stubs downstream. The plan's own quality bar
(§5.1 line "Live vendor smoke", §6 E5 row) already names a real Entra tenant +
app registration as the intended proof — this plan makes that proof exist, on
the person's subscription, and closes the biggest fidelity gap in the test
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
  the person's own account. (If the person can self-consent, the Graph-scoped
  variants below are optional add-ons.)
- **Secret hygiene unchanged**: no real secret is ever committed
  (`samples/ADP/appsettings.RealAdp.json` header rule, SECURITY.md). Real
  values live in environment variables or user-secrets on the dev machine only.
- **Local execution, not CI**: the GitHub repo is public and this is a
  production tenant — pushing a real service-principal secret into repository
  secrets hands a public-repo runner a credential into the tenant. Real-tenant
  smokes run **here** (`az login` as the person), manually or on a local
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

The library's Entra OBO grant (`TokenExchangeProvider.cs`, the
`urn:ietf:params:oauth:grant-type:jwt-bearer` path) has **no sample coverage
at all today** — Keycloak proves RFC 8693, Entra's OBO specifics (audience,
`kid` rotation, issuer aliasing) are unproven. This is the highest-value
phase.

1. App registration `credprox-e14-api`: the protected downstream audience.
   App registration `credprox-e14-client`: public client (device code flow
   enabled), delegated `User.Read` (user-consented — no admin consent).
2. Device-code sign-in as the person → a **real Entra-issued inbound token**.
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

1. `credprox-live-kv` vault (RBAC auth model, person + UAI get
   *Key Vault Secrets User* on the vault or the single secret).
2. Store `CredProx--Secrets--graph-client-secret` (the Phase 2 secret) in the
   vault; run E5 with the vault provider enabled — proving the documented
   production shape: **client secret material enters the process only from a
   real vault**, rotation = overwrite the secret + refresh interval, nothing on
   disk.

**Pass =** E5 starts and brokers a live token with the secret supplied solely
by the vault; deleting+re-adding the secret shows rotation taking effect.

## Phase 5 — Make it repeatable: the live smoke battery

- `scripts/live-azure-smoke.sh` (repo-local, safe to commit: names and env-var
  keys only, zero secret values) running Phases 1–4 as numbered checks with
  clear SKIP semantics when `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/login are
  absent — so CI (no tenant) skips, and a machine with `az login` runs it.
- `teardown-live-test.sh`: deletes RG, vault, identities; prints the `az ad
  app delete` commands for the three registrations (kept explicit because app
  deletion is tenant-wide, not RG-scoped).
- The nightly N2 header fix (E4/E5 wording) lands with this phase — trim the
  header to what actually runs (load + this battery where creds exist).

## Costs, risks, cleanup

- **Cost**: managed identities free; one vault ≈ pennies; RG empty of billable
  compute → effectively zero. **Cleanup**: one RG + three named app registrations
  + one vault, all `credprox-*`-named and deletable; teardown script included.
- **Risk**: the only genuinely new tenant exposure is three app registrations
  and two RBAC assignments; all reversible, none touching existing tenants,
  subscriptions beyond RBAC on a new RG, or billing.
- **What this can catch that fakes cannot**: Entra issuer-aliasing/audience
  mismatches in M14 validation, OBO grant shape Entra actually accepts,
  `DefaultAzureCredential` chain behaviour under CredProx's timeout/cancel
  paths, vault-latency vs cache single-flight, and any place our scrubbing
  over- or under-redacts a *real* `RequestFailedException` body.

## Sequencing and sizing

One slice (proposed **M26**), one branch. Order = 1 → 2 → 3 → 4 → 5; each
phase is independently valuable and independently shippable (the battery
script only wraps what passed). Phase 1 is the cheapest proof and can be
first-run within the same sitting as setup. M9-style adversarial pass applies
(secret handling + JWT paths are in scope). Review gates per usual §5.3 +
fresh-obj pack per ADR-0001's note.
