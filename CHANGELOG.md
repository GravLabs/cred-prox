# Changelog

All notable changes to CredProx are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html). Pre-1.0, the public API may
change between minor versions; `[Experimental]` APIs may change at any time.

## [0.9.3] - 2026-11-11

Samples, documentation, CI and benchmark reference data only — no library or public API change.

### Added

- New example E18 `samples/CallerApiKey`: caller API keys as pure configuration.
  A route requires `X-API-Key`, the key is validated against a secret-backed
  SHA-256 store (the hash is itself a `secret:` reference), a missing key and a
  wrong key get the same 401 with nothing echoed back, and the key is stripped
  before forwarding — the upstream stub's journal proves it never arrives.

### Changed

- The benchmark regression gate (`scripts/bench-compare.sh`) applies a per-arm
  allocation allowance keyed by exact `(suite, method)` pair:
  `TokenCacheBenchmarks.SingleFlight` — 64 concurrent waiters whose allocation
  follows scheduling, measured band 23,444–23,520 B at unchanged library code —
  gets max(32 B, 1% of the baseline); the SSE arms keep 8%; every other arm keeps
  the flat 32 B default. The applied allowance prints on every gated arm
  (`docs/benchmarks.md`).
- Example E6 `samples/ADP` now mirrors the known-working certificate
  arrangement: OAuth client credentials (Basic client auth, query-string grant
  kept verbatim) plus **one named mTLS connection presented on both the token
  call and the API calls**, with the certificate supplied as a base64
  passwordless PKCS#12 (PFX) — the Key Vault certificate backing-secret format
  (PEM bundles are auto-detected too). The offline stack enforces the
  certificate for real (nginx `ssl_verify_client on`, verified subject logged
  per path), records the measured token-request wire shape, and adds a Key
  Vault variant whose live certificate rotation reaching new connections is
  witnessed offline against a loopback stub.
- `docs/vendors/adp.md` matches the sample: corrected token URL, PFX/certificate
  guidance, the two-hop `Connection` wiring, and what is verified offline versus
  what needs a real ADP account.

Samples, documentation, CI and benchmark reference data only — no library or public API change.

### Fixed

- **The ADP sample's (E6) documented real-vendor switch could not work as written in
  0.9.0–0.9.2.** Two defects combined to drop the credentials silently: (a) the README
  exported the secrets under hyphenated names, which bash `export` rejects
  ("not a valid identifier"), so the values never reached the environment; and (b)
  `appsettings.RealAdp.json` declared `ClientId` and `Secrets` as empty placeholders,
  and a JSON source added after the environment overrides exported values — so even a
  correctly exported name was shadowed. Both are fixed: the variant file now commits
  only endpoint facts, and the README's export command works as written in bash, zsh
  and other POSIX shells. If you followed the old instructions, re-export as the current
  README shows: `CredProx__Credentials__adp__ClientId`,
  `CredProx__Secrets__adpClientSecret`, `CredProx__Secrets__adpClientCert`. The
  sample's smoke now runs regression guards over both documented switches.
- The **Spotify and MicrosoftGraph sample READMEs** carried the same unusable
  instruction (`export CredProx__Secrets__<hyphenated>=...`, which bash rejects), as did
  the QuickStart's env-var hint. Their published secret names are unchanged — hyphens
  are valid Key Vault names — but the delivery instruction now uses a bash-valid form
  (`env 'CredProx__Secrets__<name>=...' dotnet run`, or `dotnet user-secrets set`),
  and every corrected command was proven by running it exactly as written.
- **Migration note:** the ADP sample's secret names changed — `adp-secret` →
  `adpClientSecret`, `adp-cert` → `adpClientCert` (camelCase so the environment
  variables export cleanly). Key Vault object names follow: a vault secret named
  `CredProx--Secrets--adpClientSecret` (or `...adpClientCert`) lands as the config key
  the sample now reads.

## [0.9.2] - 2026-11-10

### Added

- Benchmark regression tracking (M34): the repository now carries a BenchmarkDotNet
  suite (`tests/CredProx.Benchmarks`) with a committed reference run per release, a
  comparison gate (`scripts/bench-compare.sh`) that fails on allocation regressions
  and warns on latency drift, and a documented procedure (`docs/benchmarks.md`).
  Every release is measured against the published previous release before it ships.

### Fixed

- Scrubbing buffer dispose window (M35): a read in flight
  when the response stream was disposed could write into, or copy from, a pooled
  buffer the pool had already handed to a new owner — cross-request exposure on
  both the pending response buffer and the output batch. Ownership now transfers:
  dispose defers each buffer's return to the last in-flight reader, which discards
  what landed late and throws `ObjectDisposedException`; post-dispose reads refuse
  on every path. Internals only. The pooling itself is new in this release, so the
  cross-request window never shipped.
- Scrubbing streams no longer keep reading the upstream after dispose. In 0.9.1 a
  scrubbing stream disposed while a read was in flight could keep issuing reads to
  the upstream response; it now stops, and a read after dispose throws
  `ObjectDisposedException`. Not reachable through the default YARP response copy,
  which disposes the stream only after its last read completes; this closes it for
  consumers that dispose a stream with a read outstanding.

### Performance

- Scrubbing hot-path allocation reduction (M35): the scrub batch and the pending
  response buffers are now pooled (`ArrayPool<byte>` seam, internals only — no
  public API change), returned cleared, and grown by rent-copy. Measured per
  request against the committed 0.9.1 baseline: response scrubbing on an OAuth
  cache hit 42,650 B → 9,729 B (about 77% less); ratio to the plain-YARP control
  arm 7.5× → 1.7×; scrubbed SSE connections 116,243 B → 81,129–88,747 B, a 24–30%
  reduction (SSE allocations vary run to run, so the figure is a range across three
  independent runs, not a point). Streaming
  semantics, redaction scope and the public API are unchanged.

## [0.9.1] - 2026-11-09

### Added

- The soak and failure-injection harness (`tools/m33-soak`) and its testing report
  (`docs/testing-report-m33.md`) are now in the repository: a compose-based fault
  battery (clock skew, vendor throttling and failure, secret rotation) with k6 load
  scenarios and a documented verdict procedure.

### Fixed

- **A negative `expires_in` no longer parks the token cache.** The
  `OAuthClientCredentials` provider treated a negative `expires_in` like an absent
  one and fell back to `DefaultLifetime` (1 h), so a token already expired at mint
  time was cached and served for up to an hour — against a real vendor, a full hour
  of requests carrying a token it will reject. A negative `expires_in` (number or
  numeric string) is now a protocol violation: the token response is rejected through
  the same path as any unusable response — callers get the documented
  `credential_unavailable` (502) problem shape and nothing is cached — and the
  warning names the field and the credential id, never the value or the token.
  `expires_in: 0` keeps falling back to `DefaultLifetime` (some IdPs use 0 for "no
  stated expiry") and now logs one warning per credential.

## [0.9.0] - 2026-11-08

### Changed

- **BREAKING — TokenExchange: https is required for inbound-validation key material by
  default.** The authority discovery document and any directly configured `JwksUri`
  carry the keys that validate **inbound** user tokens; over plain http anyone
  on the network path can swap those keys and forge a token CredProx then exchanges. The
  new `RequireHttpsMetadata` option (default `true`, the ASP.NET Core JwtBearer posture)
  governs both fetches. **Breaking precisely:** an http `JwksUri` configuration worked
  before and now fails at startup unless it opts out, naming the option; an http
  `Authority` configuration already failed every request at runtime, and now fails at
  startup with that same clear message — or works, with the opt-out. Runtime fetches
  fail closed the same way, including for a template-expanded http URL. **Migration:**
  set `"RequireHttpsMetadata": false` on that credential to keep a private-network http
  IdP working — you accept that an attacker on the network
  path can choose the keys that validate your inbound tokens, so only do it on segments
  you control. The metadata fetch also now rides the credential's per-connection egress
  client, like JWKS and token-endpoint calls. Option is additive; no API break. The
  direct JWKS cache is keyed by posture, so an opted-out credential's http-fetched keys
  can never be served to a default (https) credential on the same URI.
- **Credential attachment fails closed.** Header credentials are attached through the
  HTTP stack's own header store, which quietly rewrites or refuses some inputs. Three
  shapes of that are now refused up front with a clear error naming the credential,
  before any request leaves the proxy: an **empty value**, which the store silently
  dropped — the request used to go out unauthenticated; a **restricted header name**
  such as `Content-Length`, which used to surface as a raw internal exception at send
  time; and a header name the store **parses** (like `Date` or `Range`), which used to
  store a rewritten form of the credential — the vendor received a corrupted value on a
  request that went out. Attachment now confirms the store kept the credential
  byte-identical, and refuses if it did not.
- **JWT assertion certificate errors have one clear shape.** Signing certificate
  material that cannot be used — corrupt Base-64, unloadable certificate file, wrong
  key type for the configured algorithm — now always fails with the same clear
  "could not be loaded" error naming the certificate, instead of some malformed shapes
  surfacing a raw framework decoding exception to the caller.

### Added

- **Consumer compatibility guide and script** (`docs/consumer-compatibility.md`,
  `scripts/consumer-compat.sh`): what a consuming app can expect from CredProx packages —
  supported target frameworks, the exact refusal an unsupported framework gets,
  dependency-drift behaviour, container publish, and the trimming/AOT posture — plus a
  repeatable script that builds fresh consumer projects against the published packages
  and reports each result.

## [0.8.2] - 2026-11-07

### Added

- **Vendor config snippets** (`docs/vendors/`): complete, test-pinned `CredProx:`
  configuration blocks per vendor — ADP, Workday, Salesforce, ServiceNow, GitHub Apps,
  Microsoft Graph, Spotify. Every block is extracted by a test and bound through the
  real fail-closed startup path (a misspelled key fails CI); vendor facts are
  sample-traceable, cited to public vendor docs, or marked `UNVERIFIED:`.
- **Azure Container Apps sample** (`samples/AzureContainerApps`): the round-2 live
  validation host — proxy, independent verifiers, and the in-cluster battery in one
  image, internal-ingress only; runs and findings in `docs/live-validation-report.md`
  (round-2 section), including the managed-identity and ACR-pull identity recipes.

### Changed

- Key Vault rotation timing is now stated plainly in the add-on docs: a rotated
  `secret:` value reaches what a running proxy signs at the next credential **mint** —
  staleness is bounded by token lifetime × refresh fraction (default `0.8`), **not** by
  the provider's `ReloadInterval`. A 59-minute token caps rotation staleness near
  ~47 minutes even with 30-second polling.
- **Library code is unchanged from 0.8.1** — no public API additions, removals or
  behaviour changes; this release re-versions identical sources with docs and samples.
- The public repository history was collapsed to a single commit and the old version
  tags removed (maintainer decision): source links for 0.8.1 and earlier resolve only while
  the host retains the unreferenced commits — they are unsupported-by-construction, so
  **0.8.2 is the supported version** for stepping into source.

## [0.8.1] - 2026-11-04

### Changed

- Same code and API as 0.8.0. Republished because the public repository history was
  rewritten to remove an internal hostname; 0.8.0's source links point at a commit that
  no longer exists, so use 0.8.1.

## [0.8.0] - 2026-11-04

### Removed

- **Breaking (experimental surface): the Entra on-behalf-of exchange mode** (M27,
  ADR-0002, maintainer decision 2026-11-03): `TokenExchangeMode.EntraObo` is removed and
  `TokenExchange` speaks RFC 8693 only. The `Mode` property stays — existing
  `Mode: Rfc8693` config binds unchanged — and a config still naming the removed mode
  **fails loudly at startup binding**, never degrading to a silent RFC 8693 call. If
  you depended on the Entra OBO profile, implement a custom `ICredentialProvider`
  posting `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with `assertion`
  and `requested_token_use=on_behalf_of`; the inbound-validation and per-user-cache
  patterns in `TokenExchangeProvider` apply unchanged. No other Azure feature changed.

## [0.7.1] - 2026-10-30

### Changed

- **GitHub public pivot ships in package metadata (M25 — no functional change):**
  sources are byte-identical to `0.7.0`; this release exists so the published packages
  carry the new canonical home — repository, project and release-notes URLs point at
  `https://github.com/GravLabs/cred-prox`, and the symbol packages embed GitHub
  SourceLink (`0.7.0` as published keeps its historical metadata; published packages are
  immutable).
- **`PackageValidation` baseline rotated to `0.7.0`** (ADR-0001 rotation procedure):
  the four published `0.7.0` packages are the committed baselines, so every pack
  compares the public surface against the published `0.7.0` bytes with no feed access.
  No public API or behaviour change; the package registry scope is unchanged
  (see PUBLISHING.md).

### Known issues

- **Symbol packages embed local build paths (found post-publish):** stepping through
  CredProx `0.7.1` with symbols shows the release machine's build paths instead of the
  normalised `/_/` CI-mapped paths (GitHub SourceLink URLs are present and unaffected).
  No functional or security impact; the published packages are immutable, and the next
  release packs with the corrected procedure (see PUBLISHING.md).

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

Finalising release: benchmarks, package quality (SourceLink, deterministic build,
symbols, package READMEs, PackageValidation baseline), examples verified against the
packed `.nupkg` files, and the plan's §9 decisions closed out. Published to the
internal registry (main + tag); nuget.org postponed per plan §9.

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
