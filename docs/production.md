# Production checklist

What to configure, what to watch, and what to leave on when you deploy CredProx.
Written for operators. Every name below is a real option, config key, meter or method —
`ProductionDocGuardTests` fails the build when a `CredProx:`-rooted key or an `AddCredProx…`
call in this page stops existing at source. For rotating credentials see
[docs/operations/credential-rotation.md](operations/credential-rotation.md); for version
steps see [docs/upgrading.md](upgrading.md).

## 1. Hosting

- **TLS is your edge's job; validation is the library's.** A destination `Template` must be
  an absolute http(s) address — anything else refuses startup (`DestinationBinder`). The
  token-exchange and caller-token validators default `RequireHttpsMetadata = true` and refuse
  a plain-http `Authority`/`JwksUri` unless you explicitly opt out; the opt-out exists for
  loopback test hosts, not production (ADR-0003, `docs/adr/0003-token-exchange-require-https-metadata.md`).
- **Forwarded headers: configure them yourself.** CredProx reads no `ForwardedHeaders`
  options and sets none — nothing in the library calls `UseForwardedHeaders`. If you
  terminate TLS at a sidecar or ingress, add the ASP.NET Core forwarded-headers
  middleware in your `Program.cs` before anything that reads the request scheme or host.
- **Kestrel limits are host settings too.** CredProx ships no Kestrel or transport options
  and sets none; size `MaxRequestBodySize`, connection and timeout limits on the host. The
  pipeline streams and scrubs in rented buffers, so proxying large bodies does not scale
  allocation with body size — the exception is error normalisation, bounded by
  `CredProx:Errors:MaxNormalisedBodyBytes` (default 8192).
- **The Azure Container Apps shape** is `samples/AzureContainerApps`: `KeyVault__Uri` from
  the environment, the stock Key Vault provider at an explicit 30-second `ReloadInterval`
  (the provider's own default never polls a rotated value), `MapHealthChecks("/health")`,
  caller keys on every route.

## 2. Secrets

- Secrets reach config from one of three sources; **appsettings files committed to a repo
  are not one of them.** Use `secret:` references — `CredProx:Secrets:<name>` entries that
  hold the real value in Azure Key Vault, environment variables (`CredProx__Secrets__<name>`),
  or a key-per-file mount (`AddKeyPerFile`, as `samples/ADP` and `samples/MutualTls` do).
- In Key Vault the object name **is** the config key with the section separator doubled:
  the secret `CredProx--Secrets--<name>` lands as `CredProx:Secrets:<name>`
  (`samples/ADP`, `samples/AzureContainerApps`).
- Client certificates: a connection under `CredProx:Connections:<name>` reads exactly two
  keys — `ClientCertificate` and `ClientCertificatePassword`. The value may be a `secret:`
  reference; a PEM body starting `-----BEGIN` is detected, otherwise the value is a base64
  PFX (`ClientCertificateLoader`). A passwordless base64 PFX is the Key Vault certificate
  backing-secret format.
- Caller keys: `CredProx:Callers:<id>:Keys` entries carry `KeyId`, `KeyHash` —
  `sha256:<64 hex>` or a `secret:` reference — and optional `ExpiresAt`. The plaintext key
  never enters configuration; hashes are compared in constant time
  (`samples/CallerApiKey`).

## 3. Startup validation — what fail-closed means for a deploy

- The config topology under `CredProx:` is fixed: `Audit`, `CallerAuth`, `CallerToken`,
  `Callers`, `Connections`, `Credentials`, `Destinations`, `Errors`, `Health`,
  `KillSwitch`, `Presets`, `Resilience`, `Scrubbing`, `Secrets`, `Throttling` — plus the
  root-level `InboundKeyHeader`. Anything else under `CredProx:` refuses startup
  (`ConfigKeyValidator.RejectUnknownKeysAtStartup`); each section then validates its own
  contents, and the credential binders refuse a credential `Type` whose package is not
  registered, naming the package to add (`CredentialBinder`).
- Consequences to plan for: a typo or an inert section **fails the container at startup**,
  it does not silently ignore. A deploy that cannot validate never receives traffic — that
  is the intended behaviour; the exception message names the section, key and rule. The
  same validators ride live configuration reloads, and a rebind that fails keeps the last
  good registry serving (so a bad live edit degrades to stale-but-safe, never to open).
- A host that configures `CredProx:Throttling`, `CredProx:Resilience` or `CredProx:Health`
  without the `CredProx.Operations` package (or `CredProx:CallerAuth` without
  `CredProx.CallerKeys`, `CredProx:CallerToken` without `CredProx.CallerTokens`) fails
  startup naming the package — those features moved out of the core in 0.12 (ADR-0005).

## 4. Health, metrics and audit

- Wire the checks: `AddCredProxHealthProbes(builder.Configuration)` registers the built-in
  probes (`TokenObtainableProbe`, `CertificateExpiryProbe`) and a check named **`credprox`**.
  With `CredProx:Health:Enabled=false` neither the probe loop nor the check is registered —
  off means off (ADR-0006). `CredProx:Health:ProbeInterval` (default 5 min) and
  `CredProx:Health:CertWarningDays` (default 30) bound the loop and the expiry warning.
- One meter scope: meter name **`CredProx`** (version 0.1.0), instrumented:
  `credprox.token.cache` (hit|miss), `credprox.token.fetches` (success|failure),
  `credprox.token.fetch.duration` (seconds), `credprox.caller_throttle.rejections` (429s),
  `credprox.killswitch.rejections` (503s), `credprox.throttle.rejected`,
  `credprox.throttle.paused`, `credprox.resilience.retried`,
  `credprox.resilience.circuit_opened`, `credprox.certificate.days_to_expiry` (days),
  `credprox.health.status`. The activity source `CredProx` emits `token.fetch` spans.
- Audit: `AddCredProxAudit(builder.Configuration)` writes one record per admitted request
  to the logger category **`CredProx.Audit`** at `Information`. `CredProx:Audit:SinkTimeout`
  (default 5s) bounds a slow sink; `RedactHeaders` and `RedactJsonFields` add to the
  built-in sensitive sets, `IncludeHeaders` opts safe headers in (`CredProx:Audit:*`).
  The seam for shipping audit elsewhere is `IAuditSink`.

## 5. The kill switch

- `CredProx:KillSwitch` has exactly two keys, both lists of ids: `Clusters` and `Callers`.
  A disabled caller gets **503 `credprox.caller_disabled`**, a disabled cluster
  **503 `credprox.vendor_disabled`** — on an anonymous route a disabled cluster is still
  killed, and the caller check runs first so the code is the more specific one
  (`KillSwitchFeature`, tests in `tests/CredProx.Tests/KillSwitchTests.cs`).
- It rebinds on configuration reload, so dropping an id from the list re-admits without a
  restart; a malformed edit (misspelled key, blank id, value instead of list) is refused
  at startup and at every rebind, keeping the previous switch serving.
- Every refusal increments `credprox.killswitch.rejections` with `credprox.kind`
  (`caller` or `cluster`) and the id. The kill switch is core policy: it has no off switch.

## 6. Scrubbing and error normalisation — on by default, priced off

- Response scrubbing (`CredProx:Scrubbing:Enabled`, default `true`) keeps secrets from
  vendor bodies reaching callers; error normalisation (`CredProx:Errors:Enabled`, default
  `true`) replaces vendor error bodies with CredProx problem shapes. Turning scrubbing off
  while normalisation stays on lets unscrubbed vendor bytes into the `vendor_detail` field
  of normalised errors — that combination is documented in ADR-0006; the safe pair is both
  on, or off together with eyes open.
- Per route, the YARP metadata `CredProx.ErrorNormalisation` with value `off`
  (case-insensitive) forwards vendor error bodies byte-identical; any other value —
  including a misspelling — normalises like every other route.
- Normalisation reads at most `CredProx:Errors:MaxNormalisedBodyBytes` of a body; beyond
  the cap the body is refused rather than buffered. These are the only two safety switches
  in the pipeline: header hygiene, credential attach, the operation allow-list, the kill
  switch and refresh-on-401 have no off switch and stay non-replaceable (ADR-0006).

## 7. Logging levels that never leak

- The caller-key header (`CredProx:InboundKeyHeader`, default `X-API-Key`) is stripped from
  every outbound request whatever the route; the caller-auth header (`CredProx:CallerAuth:HeaderName`,
  default `X-CredProx-Key`) never travels upstream (`HeaderHygieneFeature`). Key material
  is absent from logs and audit by construction: literal hashes are never echoed, the
  `secret:` indirection keeps plaintext out of configuration dumps, and audit redacts the
  built-in sensitive sets (`tests/CredProx.Tests` pin both the strip and the absence).
- Recommendation, not library behaviour: keep production at `Information` or above and
  never log full configuration; `Debug`-level lines from ASP.NET Core and YARP can carry
  headers and URLs you would not want in a log pipeline. The audit record is the designed
  place for per-request facts, with your `RedactHeaders`/`RedactJsonFields` lists in front.

## 8. Container hardening for the ACA shape

- Follow `samples/AzureContainerApps`: no secrets in the image or in committed config, one
  environment-injected `KeyVault__Uri`, managed identity for vault access, explicit
  `ReloadInterval` (30 s there; the stock provider default never polls, so rotation without
  a reload interval waits for a restart), internal-only ingress, caller keys on every route,
  and `/health` wired to the `credprox` check for the platform probe.
- If you mount secret files instead of the vault, use key-per-file (`AddKeyPerFile` needs
  an absolute directory; one file per key, file name = key — the `samples/ADP` and
  `samples/MutualTls` shape) and rotate by replacing the file, which fires the same
  rebind path as everything else (`docs/operations/credential-rotation.md`).

## 9. Running several instances

- **Each instance is self-contained.** The token cache is a process singleton
  (`AddCredProxTokenCache` → `InMemoryTokenCache`, instance state only — there is no
  shared or distributed cache backend and nothing coordinating refresh across
  processes). N instances mean N vendor token streams: every instance fetches and
  refreshes its own copy of each `(credential, partition)` token. Size the vendor's
  rate limits against N times the single-instance fetch rate before scaling out
  (`tests/CredProx.Tests/InMemoryTokenCacheTests.cs` pins single-flight and expiry
  inside one instance; multi-instance behaviour is not tested — measure your own).
- **Refresh timing is identical in every instance and unjittered.** Defaults:
  refresh at 80 % of lifetime (`RefreshFraction`) with a 30 s `Skew`, and a failed
  fetch remembered for a 5 s `NegativeCacheTtl` (`TokenCacheOptions`). These are
  code-only knobs — `AddCredProxTokenCache(Action<TokenCacheOptions>)`; the type has
  no `CredProx:` section. With steady traffic, instances that started together
  reach their refresh points near-simultaneously — each entry's refresh time is
  computed from its own acquisition start, so a fleet that started minutes apart
  keeps refreshing minutes apart; that burst is the vendor's problem only if it is
  rate-limited, and a broken credential makes every instance retry within seconds
  because of the short negative TTL.
- **The health probe adds its own per-instance traffic.** With `CredProx:Health:Enabled`
  (default `true`) the `TokenObtainableProbe` obtains tokens through the same cache
  path on every `CredProx:Health:ProbeInterval` tick (default 5 min), per instance.
- **Budgets are enforced per instance, so fleet totals multiply.** `CredProx:Throttling`
  limits are "per cluster, never global" and live in an in-process fixed-window
  limiter; caller budgets (`CredProx:Callers:<callerId>:Limits`, refusal
  `429 credprox.caller_throttled` with `Retry-After`) likewise. To give a caller
  100 req/s across N replicas, configure `100/N` per instance. `CredProx:Resilience`
  retry and breaker state is per instance too — a flapping vendor can open N
  independent breakers.
- **The kill switch lands per instance, at each one's next request.** Every instance
  rebinds `CredProx:KillSwitch` on config reload, so a push that reaches all
  instances disables all of them without a restart (`KillSwitchRegistryProvider`);
  it does not cancel a request already forwarded — in-flight work completes.
- **Live reload covers exactly five areas: Credentials, Callers, KillSwitch,
  Destinations, Connections** — each registry rebinds on the configured secret
  source's change token and keeps the last good one serving when a rebind is
  refused, and the caller key table reloads with the caller registry
  (`CredProx:Callers:<callerId>:Keys`). That source is the configuration by
  default, so reloads land; Callers additionally watch the configuration reload
  token itself, and a host that replaces the secret source with one that does
  not fire on configuration reload would not see config-only edits land without
  a restart.
  Everything else is read once at startup: `CredProx:Scrubbing`, `CredProx:Errors`,
  `CredProx:Audit`, `CredProx:Health`, `CredProx:Throttling`, `CredProx:Resilience`,
  `CredProx:CallerAuth` and `CredProx:CallerToken` — changing those across a fleet
  needs a rolling restart (reload tests: `tests/CredProx.Tests/ConfigReloadIntegrationTests.cs`).
