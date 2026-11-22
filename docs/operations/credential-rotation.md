# Credential rotation

What to rotate, how each secret kind rotates, and which rotations genuinely need
a restart. Each step cites the test or sample that proves it; where no witness
exists the absence is named, not papered over. The config-key shapes are in
[../production.md](../production.md) §2; what reloads live across a fleet is §9.

| What you rotate | How | Restart? |
|---|---|---|
| Vendor secret behind a `secret:` reference | replace the value at its source | no — once the config source delivers it |
| Caller key | add a second `Keys` entry, retire the first | no |
| Client certificate | replace the `ClientCertificate` value | no |
| Hmac / JWT-assertion signing key | replace the referenced secret | no |
| Issuer keys under the same `Authority` | nothing — the JWKS cache picks them up | no |
| `Authority`, `Audience`, `MaxTokenAge` | config change + rolling restart | yes |
| Secret delivered only via environment variables | process restart | yes |

## 1. Vendor secrets (client secrets, API keys)

- Every vendor secret reaches the library as a `secret:<name>` reference resolved
  from `CredProx:Secrets` (the configuration secret source), and values are expanded
  **at use time** — per token fetch (`OAuthClientCredentialsProvider`), per signed
  request (`HmacProvider`), per assertion (`JwtAssertionProvider`), per lookup
  (`StaticKeyProvider`). A replaced value therefore applies to the next fetch with
  no restart, as long as the configuration source actually re-delivered it
  (the configuration secret source tests pin that a reload
  updates resolved values and that the change token fires —
  `tests/CredProx.Tests/ConfigurationSecretSourceTests.cs`).
- The source decides how the new value reaches the process:
  - **Key Vault** — `AddAzureKeyVault` with an explicit `ReloadInterval`
    (30 s in `samples/AzureContainerApps` and `samples/MicrosoftGraph`). That
    extension comes from the host-side package
    `Azure.Extensions.AspNetCore.Configuration.Secrets`; its `ReloadInterval`
    default is null — never polls — which is provider behaviour CredProx does
    not pin, so without that line a rotated vault value waits for a restart
    (`samples/MicrosoftGraph/README.md` states it outright). The rotation is witnessed offline: the ADP smoke rotates its vault
    stub and new connections carry the new value without a restart
    (`tests/CredProx.SampleSmokes/AdpSmokeTests.cs`; `samples/ADP/README.md`,
    `./rotate-kv-stub.sh`).
  - **Key-per-file mount** — the provider watches the directory; rotate by
    replacing the file, file name = key (`samples/MutualTls`, "Certificate
    rotation, live": rewrite the file, the next connection presents the new
    value). No test drives `AddKeyPerFile` directly — the sample and its smoke
    (`tests/CredProx.SampleSmokes/MutualTlsSmokeTests.cs`) are the witness.
  - **Environment variables** — there is no hot-reload signal for this source:
    the .NET environment provider snapshots at process start (host behaviour, not
    a CredProx guarantee), so env-delivered secrets rotate with the process.
- Rotation does not revoke tokens already cached: they serve until their refresh
  point. A vendor that must cut access immediately relies on refresh-on-401,
  whose trigger is narrow: a 401 invalidates the cached token and replays the
  request only where CredProx is willing to retry it — idempotent methods, or
  `RefreshOn401Options.RetryNonIdempotent` (default off) — and only with a
  known-length body at or below `MaxRetriedBodyBytes` (default 1 MiB). A
  streamed or over-cap body gets the upstream 401 untouched, and the cached
  token is not invalidated at all (the refresh-on-401 handler,
  `src/CredProx/Pipeline/TokenRefreshHandler.cs`).
  So "cut access immediately" holds for small-body idempotent traffic; against
  POST-heavy or streaming callers the cut lands no sooner than each cached
  token's own refresh point.

## 2. Caller keys

- The intended shape is a **dual-key window**: add a second entry under
  `CredProx:Callers:<callerId>:Keys` (distinct `KeyId`), run both while valid,
  then drop the old entry (`samples/PerCallerCredentials/README.md`;
  `tests/CredProx.Tests/CallerStoreTests.cs` pins two active keys resolving,
  `CallerAuthIntegrationTests` authenticates through both rotated values). Or
  schedule retirement with per-key `ExpiresAt` (`samples/CallerApiKey/README.md`)
  — an expired key fails like an unknown one.
- The change lands on configuration reload, per instance: the caller registry
  swaps generations atomically, the hashed key table is rebuilt inside every
  accepted rebind, and a refused edit keeps the previous generation serving
  (`tests/CredProx.Tests/CallerRegistrySingleFlightTests.cs` pins one-refused-
  and one-accepted-reload; `CallerKeysEagerTableTests` pins a key-only rotation
  taking effect within the reload window).
- **0.13.0 is the release that made env-cased rotation instant.** On 0.12.0 a
  host whose caller config arrives upper-cased (an environment delivers
  `CREDPROX:CALLERS:…`) could keep admitting a retired literal `KeyHash` until
  restart — CHANGELOG 0.13.0, Fixed: "the rebind gate filtered caller keys
  case-sensitively while every consumer binds them case-insensitively, so the
  gate never saw the change. The rebind now sees it in any key casing. The
  published 0.12.0 carries the defective gate; upgrading fixes it." Witness:
  `CallerRegistrySingleFlightTests.LiteralKeyHashRotation_EnvVarCasedCallerKeys_RebindsAndRotates`.
  On 0.12.0, rotate the hash through a `secret:` reference (the change token fires
  regardless) or restart after rotating.
- Hashes only: the new entry carries `sha256:<64 hex>` or a `secret:` reference —
  plaintext keys never enter configuration.

## 3. Client certificates for vendor connections

- The surface is the two keys under `CredProx:Connections:<name>`: replace the
  `ClientCertificate` value (PEM body or base64 PFX; `ClientCertificatePassword`
  if the PFX has one). The connection compares the secret value on each refresh,
  reloads the certificate only when it changed, and bumps a monotonic `Version`
  so the forwarder rebuilds its client for the new material
  (`ClientCertificateConnection`; the connection binder tests,
  `tests/CredProx.Tests/ConnectionBinderTests.cs`, pin reload + version bump;
  `CredProxForwarderHttpClientFactoryTests` pins the reuse stamp across rotation).
- A bad replacement fails safe: a rebind whose certificate will not load keeps
  the previous certificate serving and logs only the exception type
  (the connection binder tests pin the keep-serving path —
  `tests/CredProx.Tests/ConnectionBinderTests.cs`).
- End-to-end witness: `tests/CredProx.E2ETests/NginxMTlsTests.cs` rotates a real
  client certificate over real sockets and nginx sees the new one on the next
  connection. Watch expiry before it bites: `CertificateExpiryProbe` reports
  Degraded inside `CredProx:Health:CertWarningDays` (default 30), gauge
  `credprox.certificate.days_to_expiry`.

## 4. Signing keys

- **Outbound HMAC credential** (the core's `Hmac` type): one `Secret` option, `secret:`
  reference allowed — replace the referenced value and the next signed request
  uses it (`HmacProvider` signs per request, no restart). There is no
  current/next pair, so any vendor-side accept-old-and-new window is the
  vendor's. No test rotates an HMAC secret live — per-request resolution is the
  mechanism; treat it as untested ground and verify against your vendor.
- **JWT-assertion credential** (`CredProx.Identity`): `SigningKey` or
  `SigningCertificate`, mutually exclusive, resolved per assertion — the same
  replace-and-go, the same test absence.
- **Inbound caller tokens** (`CredProx.Identity`): there is no signing key to
  rotate — caller tokens are validated against the issuer's JWKS. Rotating the
  issuer's keys under the same `Authority` needs nothing from CredProx because
  the ASP.NET Core JWT handler's JWKS cache picks up the new kid — framework
  behaviour on the host side, not a CredProx-pinned guarantee; the vendor-token direct-JWKS path evicts its cache only on
  key-not-found,
  `tests/CredProx.Tests/TokenExchangeProviderM31Tests.cs` pins that rule.
  Changing `Authority`, `Audience` or `MaxTokenAge` changes a startup snapshot:
  config change plus rolling restart — `MaxTokenAge` is documented restart-only
  on the option itself (`CallerTokenOptions`).

## 5. What still needs a restart

- Secrets that reach the process only through environment variables.
- The startup-only sections listed in [../production.md](../production.md) §9:
  `CredProx:Throttling`, `CredProx:Resilience`, `CredProx:Audit`,
  `CredProx:Errors`, `CredProx:Scrubbing`, `CredProx:Health`,
  `CredProx:CallerAuth`, `CredProx:CallerToken`.
- A Key Vault wired without `ReloadInterval` — until that line exists, vault
  rotation waits for a restart.
