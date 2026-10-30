# Changelog

All notable changes to CredProx are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html). Pre-1.0, the public API may
change between minor versions; `[Experimental]` APIs may change at any time.

## [Unreleased]

### Changed

- **GitHub public pivot (M25 — no functional change):** the canonical source home is now
  `https://github.com/GravLabs/cred-prox`. Package metadata (repository, project and
  release-notes URLs) and SourceLink point there **from the next release onward**; CI
  workflows moved to `.github/`; `PackageValidation` now validates against the published
  baseline packages committed under `build/baselines` (ADR-0001), so `dotnet pack` needs
  no particular package feed on any machine. No public API or behaviour change; the
  package registry scope is unchanged (see PUBLISHING.md).

## [0.7.0] - 2026-10-21

### Added

- **Session-cookie login** (plan §8.1, M23): `LoginExchangeOptions` gains `Location`
  (`Header` default, or `Cookie`) and `Name` — in cookie mode the credential is replayed
  as a single `Cookie: <name>=<value>` header instead of an Authorization header, with the
  cookie name defaulting to `ResponseField` (the cookie the login returned). Cookie
  placement **replaces the whole `Cookie` header, never merges**: a caller-supplied
  `Cookie` never rides along to the vendor next to the session. Values containing `;`,
  CR, LF or NUL are refused (no cookie smuggling or request splitting), and since M24
  so are values outside ASCII — request headers travel as Latin-1 bytes, so a non-ASCII
  cookie value could not reach the vendor faithfully and is refused rather than
  silently maimed. Also refused: `Query` placement and `AttachPrefix` with
  `Location: Cookie`, and a cookie config must
  name its cookie (`Name` or `ResponseField`) with a valid RFC 6265 name. Extraction and
  placement are independent — `Response: Cookie` pairs with any placement, and
  `Location: Cookie` works with a token extracted from body, JSON path or header — and
  the cache, per-partition secrets, refresh-on-401, response scrubbing (§8.2) and audit
  apply to cookie credentials unchanged. Example E16 `samples/SessionCookie` is the
  generic successor to the original Cayuse demo: form login → `Set-Cookie`, per-
  environment accounts and secrets via `{partition}` behind a strict `X-API-Env`
  allow-list (the F6 host-swap bug class answers `400 credprox.partition_not_allowed`),
  a server-side session expiry refreshed through the 401 without the caller noticing,
  and the session scrubbed out of the stub's echo field.
  **Note:** `LoginExchangeOptions.Name` on the concrete options type is now nullable and
  unset by default; the effective attachment name — `Authorization` in header mode, the
  response cookie's name in cookie mode — is resolved through the attachment interface.
- **Vendor error normalisation** (plan §8.5, M24): a vendor's `4xx`/`5xx` text-like
  error body is rewritten into a uniform RFC 7807 `application/problem+json` document,
  on by default — the caller speaks one error dialect for vendor failures and the
  proxy's own failures alike. The vendor's status is preserved verbatim (normalisation
  reframes, it never re-decides) and the rewrite is lossless: the vendor's payload rides
  along as the `vendor_detail` extension member — parsed JSON when it parses, raw text
  otherwise — beside `vendor_content_type`, under the uniform
  `extensions.code: credprox.vendor_error`. The document's `type` identifies the origin:
  vendor rewrites carry `urn:credprox:errors:vendor`, and every problem the proxy itself
  produces now carries `urn:credprox:errors:proxy` (a new `type` member on proxy problem
  bodies, additive). The rewriter runs on already-scrubbed bytes — it is registered after
  the §8.2 scrubber in the same `ShapeResponse` stage, whose ordering the pipeline keeps
  stable — so a credential a vendor reflects inside its error page reaches
  `vendor_detail` only as `[redacted]`. Opt-outs: `CredProx:Errors:Enabled=false`
  globally, and route metadata `"CredProx.ErrorNormalisation": "off"` per route. Limits:
  only bodies up to `CredProx:Errors:MaxNormalisedBodyBytes` (default 8192) are
  normalised — the cap covers the buffered compressed bytes and the decoded form
  (a gzip bomb cannot decode past it into the document) — and a larger body is forwarded
  **byte-identical, never truncated**, with a warning. `HEAD` responses,
  `text/event-stream`, non-text or unknown content types, bodies whose declared charset
  is not UTF-8/US-ASCII (never re-encoded: a Latin-1 or UTF-16 body would arrive
  corrupted in the embed, so its exact bytes flow instead), and undecodable or chained
  content encodings likewise flow byte-identical; the replacement carries the document's
  exact `Content-Length`, and vendor response-level headers (`Retry-After` and friends)
  survive untouched. Example E16 shows both postures: `/crm/...` normalises the vendor's
  `SKU_NOT_FOUND` 404, the opted-out `/crm-raw/...` route forwards it as written.
  **Behaviour change:** callers that previously parsed the vendor's own error bodies
  from a CredProx endpoint now receive problem documents — pin those routes with
  `"CredProx.ErrorNormalisation": "off"` or set `CredProx:Errors:Enabled=false`.

## [0.6.0] - 2026-10-20

### Added

- **Kill switch** (plan §8.4): `CredProx:KillSwitch` takes a vendor or a caller out of
  service by configuration alone — `Clusters` and `Callers` list the ids (case-insensitive,
  free-form names matched against the YARP cluster id and the caller id). A request hitting
  a disabled cluster answers `503 credprox.vendor_disabled`, a disabled caller
  `503 credprox.caller_disabled` — at the new `Stage.ApplyKillSwitch`, right after caller
  authentication and before partition resolution, credential attachment and forwarding, so
  a killed request never spends a token or touches the upstream (§3.4). The key of a
  disabled caller must still validate first: the switch removes a caller from service, it
  is never an anonymous bypass. The lists reload live (a failed reload keeps the previous
  switch state guarding), and the section is fail-closed like every other — a misspelled
  key, a map-shaped entry (`Clusters:acme = true`), a single value instead of a list or a
  blank id all refuse startup and reload, because an unarmed kill switch reads exactly like
  a vendor that was never disabled. Meter: `credprox.killswitch.rejections` tagged
  `credprox.kind` (`caller`/`cluster`) + the disabled id.
- **Consent-required signalling** (plan §8.3, M19): a credential provider that knows the
  end user has not yet authorized the application throws the new `CredProx.Abstractions`
  `ConsentRequiredException(authorizeUrl, message)`. The credential attach feature turns it
  into `401 credprox.consent_required` (`application/problem+json`) carrying the URL as the
  problem's `authorize_url` extension member, and does not forward — instead of the generic
  `502 credprox.credential_unavailable` every provider exception used to get. The member is
  included only for an absolute http(s) URL without embedded credentials; a relative
  reference, a non-browser scheme such as `javascript:`, or userinfo is dropped from the
  response (the consent problem lands either way). On the refresh-on-401 path a consent
  signal cannot rewrite the response: the upstream's own 401 is returned untouched and no
  retry is attempted. `samples/CustomPlugin` shows a plugin raising it from a vendor answer.
- **Response secret scrubbing** (plan §8.2, M20): when the upstream reflects back a
  credential the pipeline injected — an error page echoing the request, an echo endpoint,
  a stack trace — the caller now receives `[redacted]` in its place, never the value.
  Response headers and text-like bodies (`text/*`, JSON/XML/JavaScript shapes, form posts,
  YAML) are scanned; gzip/deflate/br bodies of those types are transparently decoded,
  scrubbed and forwarded decompressed, and the URL-encoded form of a query-placement
  credential is covered too. The scan engages only when the request actually injected a
  value, so every other response — binary, unknown, or credential-free — flows through
  byte-identical. On by default; opt out globally with `CredProx:Scrubbing:Enabled=false`.
  `text/event-stream` responses scrub **per event**: each event is checked and flushed
  as it completes, so streaming clients keep receiving events as the provider writes
  them instead of waiting behind the matcher's look-ahead. Four documented residues:
  bodies of non-text content types are not scanned; a content encoding without a
  streaming decompressor in .NET (zstd) is warned about and forwarded untouched; the
  matcher matches UTF-8 bytes, so a body in a non-UTF-8 character set carries the value
  through; and a secret split across an SSE event boundary is not caught — each event is
  matched on its own bytes. Scrubbing can change the body length, so a scrubbed response drops
  the upstream `Content-Length` and the proxy re-frames it — clients see the scrubbed
  length or chunked framing, never a stale one.
- **The response direction of the plugin model is live** (§3.1, §3.5):
  `CredProx.Abstractions.IResponseFeature` — advertised since 0.3 but never dispatched —
  now runs, stage-ordered at the new `Stage.ShapeResponse`, at the end of the outbound
  pipeline before any byte of the upstream response is copied to the caller. The built-in
  scrubber is the first feature on it; a registered plugin runs on the same contract. A
  failing response feature is fail-closed: the raw upstream bytes are never forwarded over
  its failure.
- Example E15 `samples/AgentEgress`: the AI agent egress shape (plan §8.3) — an MCP
  server / agent runtime calls a Salesforce-shaped vendor through CredProx holding only
  its own caller API key. Per-agent operation allow-lists are the tool boundaries (the
  CRM agent reads, the support agent opens cases, neither can do the other's job);
  the Salesforce `OAuthClientCredentials` + `FormPost` client auth is pure config; two
  agents share one credential whose cached session token serves both (an issuance counter
  proves it); and the response scrubber removes the session token the stub's
  `debug_authorization` field echoes back. The README carries the production MCP
  topology and how to point it at a real org. No library changes.

### Changed

- **Breaking (config): unknown keys under the remaining `CredProx` sections now refuse
  startup** (plan §3.3, M17). `CredProx:Destinations` and `CredProx:Connections` also refuse
  a config reload (the previous registry keeps serving), naming the destination/connection
  and the key; `CredProx:Audit`, `CredProx:Health`, `CredProx:Throttling` and
  `CredProx:Resilience` fail startup eagerly; and at the `CredProx` root an unknown key or a
  misspelled section name (`Throteling`, `Credentails`) fails startup instead of silently
  disabling the feature. Entries of the per-cluster dictionaries are validated against their
  cluster options type (cluster names stay free-form). Previously all of these were dropped
  by the configuration binder without a word. Fix misspelled keys before upgrading: a
  destination takes `Template`, `Partition`, `Allowed`, `StripHeader`; a connection takes
  `ClientCertificate` and `ClientCertificatePassword`.
- **Breaking (config): entries of CredProx lists must now be indexed** (plan §3.3, M18).
  The configuration binder reads list elements by index and ignores every other child key,
  so an entry like `CredProx:Destinations:acme:Allowed:oops = prod` configured nothing in
  silence; it now refuses startup with an error showing the index shape
  (`Allowed:0`, `Allowed:1`, …). A nested block under an index (`Allowed:0:Id = prod`) is
  rejected for the same reason. Well-formed configs are unaffected.

## [0.5.0] - 2026-10-19

### Changed

- **Breaking (config): unknown keys under `CredProx:Callers` or `CredProx:CallerAuth` now
  refuse startup** (and a config reload is refused, keeping the previous callers serving)
  with an error naming the caller and the key. Previously they were silently ignored — and
  a typo in an allow-list entry (`PathPatterns` for `Paths`) admitted that caller to
  **every** route. Fix any misspelled keys before upgrading: caller-level keys are `Keys`
  and `Operations`; key entries take `KeyId`, `KeyHash`, `ExpiresAt`; operation entries
  take `Route`, `Methods`, `Paths`; `CallerAuth` takes `HeaderName`.
- **Breaking (config): unknown keys under `CredProx:Credentials` now refuse startup** (and a
  config reload is refused, keeping the previous registry serving) with an error naming the
  credential and the key. Previously the binder silently ignored them — a misspelled optional
  field (`Scopee` for `Scope`) bound to nothing and the credential ran without the setting it
  was meant to have. The allowed keys are the credential type's options properties — derived
  by reflection, so a plugin credential declares its own keys simply by having them on its
  options type — plus `Type` and `Preset`; nested blocks (`Partition`, `Basic`, `Form`, …)
  are checked level by level, and a nested block under a single-value key (a `Partition`
  shape written under `Scope`) is rejected too. Validation runs on the effective post-preset config, so a typo
  inside a host preset is caught exactly like one the host wrote. Migration note: a variant
  config that layered `null` over another type's fields to "clear" them (the pattern
  `samples/MicrosoftGraph` used before its M16 rework) now fails — declare each variant's
  credential with only the keys its active `Type` owns.

### Added

- **Per-caller request budgets** (plan §3.7): a caller may declare
  `CredProx:Callers:<id>:Limits` with `PermitsPerInterval` + `Interval` and an optional
  `Clusters:<clusterId>` override (unset override fields inherit the caller default;
  `PermitsPerInterval: 0` disables the budget for that cluster). One fixed window per
  caller × cluster, in-memory, keyed by caller id — key rotation and (for JWT callers)
  per-user tokens share the caller's budget. Over budget answers
  `429 credprox.caller_throttled` with `Retry-After` (seconds to window reset), distinct
  from the cluster limiter's `429 credprox.throttled`; the budget runs at the new
  `Stage.ApplyCallerBudget` (after destination resolution, before credential attach), so
  a rejected call never spends a provider permit or a token. Meter:
  `credprox.caller_throttle.rejections` tagged `credprox.caller` + `credprox.cluster`.
  Unknown keys under `Limits` refuse startup like the rest of `Callers` (M14a) — a typo
  in a limit never silently means unlimited. Single-instance scope: windows reset on
  restart and when a reload changes that caller's limits. **Binary note:** the new
  optional parameters on `CallerDefinition`'s constructor and on
  `CredProxRequestState.AbortAsync` are source-compatible but replace the previous
  signatures at the binary level — recompile against 0.5.0 rather than swapping the DLL.
- Example E13 `samples/AiGateway` now shows per-caller budgets: a third caller
  `batch-app` declares 2 requests/minute; its third call answers
  `429 credprox.caller_throttled` with `Retry-After` while the other callers keep their
  full budget.
- **`TokenExchange` credential type** (plan §3.6): the caller's inbound user token is
  validated by CredProx (signature, issuer, **audience** — mandatory, lifetime) through
  OIDC discovery or an explicit JWKS, then exchanged at the configured endpoint in
  `Rfc8693` mode (`subject_token`/`subject_token_type`, RFC 8693 `audience` parameter) or
  `EntraObo` mode (`assertion` + `requested_token_use=on_behalf_of`). The exchanged token
  is cached **per user** (`(credential, partition + subject)`) and attached to the
  request; the inbound token is never cached, logged or forwarded. A missing inbound
  token answers `401 credprox.inbound_token_missing`, a rejected one
  `401 credprox.inbound_token_invalid` (failure kind only, never the token), an exchange
  failure `502 credprox.credential_unavailable`. Supporting public API:
  `CredentialRequestContext` gains `InboundToken` (populated only for providers whose
  options implement the new `IRequiresInboundToken` marker) and `CachePartition` (the
  provider's effective per-user key, so refresh-on-401 invalidates exactly that entry);
  `CredProx.Abstractions` gains the sealed `InboundTokenRejectedException`. The core now
  depends on `Microsoft.IdentityModel.Protocols.OpenIdConnect` for inbound validation.
- Example E14 `samples/TokenExchange`: the whole flow against real Keycloak 26.2
  (standard token exchange) — two users each get their own exchanged downstream token, a
  forged inbound token dies at validation with no exchange attempted, the caller key is
  still required, and the downstream's audience check proves the inbound token never
  reaches it.
- Example E13 `samples/AiGateway`: the AI provider gateway — internal apps authenticate
  with their own caller API keys, CredProx injects the real provider key (`StaticKey`
  header), enforces per-caller operation allow-lists (a chat-only caller cannot reach
  files/admin endpoints), throttles the provider cluster, and audits every call. SSE
  streaming passthrough is proven by an in-process provider stub that flushes two events
  400 ms apart. No library changes.

## [0.4.0] - 2026-10-17

### Changed

- **Breaking: the library ships no built-in vendor presets.** The six presets
  (`spotify`, `microsoft-graph`, `github-app`, `keycloak`, `adp`, `cayuse`) are removed.
  Every vendor's full setup now lives in its own isolated sample as plain config:
  `samples/Spotify`, `samples/MicrosoftGraph`, `samples/GitHubApp`, `samples/OAuthKeycloak`,
  `samples/ADP` and `samples/LoginExchange`. A config that still names a removed preset
  fails at startup with an error naming it and pointing at the matching sample.
  **Migration:** copy the credential config from the matching sample's `appsettings.json`
  into your `CredProx:Credentials:<name>` section — the values are exactly what the preset
  used to supply, and behaviour is unchanged.
- The preset **mechanism** stays: user-defined presets (`CredProx:Presets:<name>` in config
  or a custom `IPresetSource`) still layer a JSON fragment beneath host configuration,
  field by field, with preset-introduced `secret:` references validated at startup.
  Packaging a vendor's fixed facts as a preset is now a host/community choice, not
  something the library ships.
- Examples: E6 is now `samples/ADP` (ADP's OAuth client credentials + mTLS shape, split out
  of the deleted `HrIntegrations` sample); new E12 `samples/LoginExchange` demonstrates the
  vendor-neutral login exchange with `{partition}` per-environment partitions and the
  partition allow-list.

## [0.3.0] - 2026-10-16

Finalizing release: benchmarks, package quality (SourceLink, deterministic build,
symbols, package READMEs, PackageValidation baseline), examples verified against the
packed `.nupkg` files, and the plan's §9 decisions closed out. Published to the Gitea
registry (main + tag); nuget.org postponed per plan §9.

## [0.3.0-preview.3] - 2026-10-15

Milestones M8–M10 (plan §7): resilience, signing credential types, presets, and the
plugin toolkit.

### Added

- Outbound **throttling** (rate limiting with `Retry-After` honouring) and the
  **resilience adapter**: per-cluster retry, circuit breaker and timeout pipelines
  composed around the YARP HttpClient (`credprox.*` failure statuses, e.g. `503
  credprox.circuit_open`, `504 credprox.upstream_timeout`).
- **`JwtAssertion` credential type** (RFC 7523 client-assertion flow — GitHub App
  installation tokens via the `github-app` preset) and **`Hmac` credential type** with
  canonical-string configuration and body buffering limits.
- **Vendor presets**: a preset is a JSON fragment of fixed vendor facts layered beneath
  host configuration (every host field wins, field by field). Six built-ins: `spotify`,
  `microsoft-graph`, `github-app`, `keycloak`, `adp`, `cayuse`; custom sources via
  `IPresetSource`. Preset-introduced `secret:` references are validated at startup like
  the host's own.
- **`CredProx.Testing` package**: `FakeUpstream`, `FakeTokenServer`, `CapturedLogSink`
  and conformance suites so credential-type plugins prove the same secret-hygiene and
  refresh behaviour as the built-ins.
- Examples: E8 `GitHubApp`, E9 `HmacSigning`, E10 `CustomPlugin` (~50-line credential
  type, conformance-tested), E11 `Operations` (throttling, vendor pause, breaker,
  health under load).

## [0.3.0-preview.2] - 2026-10-14

Milestones M6–M7: caller identity and observability.

### Added

- **Caller authentication**: inbound API keys (constant-time comparison), per-caller
  credentials mapped to vendor accounts, and fail-closed operation allow-lists
  (method/path/route).
- **Credential health probes** and the **audit log**: every credential use audited with
  redaction of secret values, pluggable `IAuditSink`s.
- Example E7 `PerCallerCredentials` (two callers, one route, different vendor accounts;
  read-only caller blocked from POST; audit records).

## [0.3.0-preview.1] - 2026-10-14

Milestones M1–M5: the core library.

### Added

- `CredProx.Abstractions`: the plugin contract — credential providers, pipeline/request/
  response/connection features, secret sources, token cache, partition sources, stages.
- **Token cache** with per-credential/per-partition scoping, single-flight refresh,
  early refresh and negative caching; **secret sources** with per-credential scoping and
  startup validation.
- Built-in credential types: `OAuthClientCredentials`, `LoginExchange`, `StaticKey`,
  `TokenCredential`; refresh-on-401.
- **Destinations** (static and templated with fail-closed allow-lists), **connections**
  with client-certificate configuration and reload, mTLS per cluster.
- Configuration-only vendor integration: credentials, destinations, connections and
  callers bind from `appsettings`/environment with live reload and reload-time
  validation (a bad reload is refused; the previous configuration keeps serving).
- Container E2E tests (Keycloak OAuth, nginx mTLS) and examples E1–E6
  (`QuickStart`, `OAuthKeycloak`, `MutualTls`, `Spotify`, `MicrosoftGraph`,
  `HrIntegrations`).
