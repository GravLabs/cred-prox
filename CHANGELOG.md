# Changelog

All notable changes to CredProx are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html). Pre-1.0, the public API may
change between minor versions; `[Experimental]` APIs may change at any time.

## [Unreleased]

## [0.13.0] - 2026-11-19

This release makes the health switch really turn health off, fixes caller-key
rotation so a rotated key stops working from an upper-cased configuration
source immediately instead of at restart (the published 0.12.0 carries the
defective gate), and removes the per-request allocation the credential-attach
arms picked up in 0.12.0.

### Changed

- `CredProx:Health:Enabled=false` now means off: the probe loop and the `credprox`
  ASP.NET Core health check are no longer registered at all. Previously the switch
  stopped the probes but the `credprox` check stayed on the endpoint reporting Healthy
  with "No CredProx health probes have run yet" — a host that turned health monitoring
  off could not tell it apart from monitoring that had simply not run its first round.
  The health options, built-in probes and snapshot stay registered and resolvable
  (ADR-0006).

### Fixed

- The forwarder's measured-body hand-off no longer installs a per-request delegate
  on every CredProx-routed request. The hand-off shape travels as a flag on
  `CredProxRequestState` and the rewrite lives inside
  `CredProxRequestState.MeasureOutgoingBodyAsync`, removing the ~113 B per request
  the credential-attach arms carried since 0.12.0 (docs/benchmarks.md, "Accepted
  release-delta allocations"). The bytes flowing onward are unchanged.
- A host that feeds its caller configuration through an upper-cased source — an
  environment (`CREDPROX:CALLERS:…` keys arrive upper-cased) or a key-per-file
  mount — and rotates a caller's literal `KeyHash` without the configuration
  secret source firing kept admitting the retired key until restart: the rebind
  gate filtered caller keys case-sensitively while every consumer binds them
  case-insensitively, so the gate never saw the change. The rebind now sees it
  in any key casing. The published 0.12.0 carries the defective gate; upgrading
  fixes it.

## [0.12.0] - 2026-11-17

This release splits single features out of the `CredProx` package into small add-on
packages (ADR-0005). A host's setup is one core call plus the call of each package it
actually uses. The split is fail-closed in both directions: a credential naming a
packaged `Type` without its package fails startup naming the package to add, and a
configured feature section whose package is absent fails the same way — no written
configuration ever sits inert.

| Package | Carries | Setup from 0.11.0 |
|---|---|---|
| `CredProx` | the core pipeline: token cache, configuration secret stack, `StaticKey`, caller policy, header hygiene, audit, problem responses | the one call `AddCredProx(builder.Configuration)` replaces the granular `AddCredProxTokenCache` + `AddCredProxConfigurationSecrets` + `AddCredProxBuiltInCredentials` + `AddCredProxCredentials` (each stays public for hosts that want the control) |
| `CredProx.Abstractions` | the plugin contracts every other package builds on | unchanged — referenced transitively |
| `CredProx.OAuth` | `OAuthClientCredentials`, `TokenExchange`, `JwtAssertion` | add the package reference and call `AddCredProxOAuth()`; configuration is unchanged |
| `CredProx.Hmac` | `Hmac` request signing | add the package reference and call `AddCredProxHmac()`; configuration is unchanged |
| `CredProx.LoginExchange` | `LoginExchange` session-login credential | add the package reference and call `AddCredProxLoginExchange()`; configuration is unchanged |
| `CredProx.Operations` | the outbound throttle, the resilience adapter, credential health probes | add the package reference and call `AddCredProxThrottling()`, `AddCredProxResilience()` and `AddCredProxHealthProbes()`; configuration sections are unchanged |
| `CredProx.CallerKeys` | caller API keys | add the package reference; the call `AddCredProxCallerAuthentication()` is unchanged, and hosts referencing the moved types recompile |
| `CredProx.CallerTokens` | agent caller tokens (OIDC access tokens mapped to callers) | add the package reference; the call `AddCredProxCallerTokenAuthentication()` is unchanged, and hosts referencing the moved types recompile |
| `CredProx.AzureKeyVault` | the `TokenCredential` credential type over `Azure.Identity` | unchanged: `AddCredProxAzureTokenCredential(credential)` |
| `CredProx.Testing` | the conformance suites a third-party credential type runs against | unchanged |

### Added

- The `CredProx.Hmac` package [Experimental]: the `Hmac` credential type, its signer and
  the signing stage move out of the core into an add-on (ADR-0005), like the caller
  add-ons. The host adds the package and calls `AddCredProxHmac()`; configuration is
  unchanged (`Type: Hmac`), and a credential naming `Type: Hmac` without the package
  fails startup naming the package to add. New public seam for features that need the
  whole request body: `CredProxRequestState.MeasureOutgoingBodyAsync(maxBytes, ct)`
  counts the bytes itself and installs the measured copy as the body that flows onward —
  it returns `null` only when its own count passed the cap (so a stage answers `413` on a
  measured overrun and nothing else), any other failure keeps its own cause, and on the
  forwarder the read and the install both go through the request body the forwarder pumps
  at send time.
- The `CredProx.LoginExchange` package [Experimental]: the `LoginExchange` credential
  type, its options and its startup validator move out of the core into an add-on
  (ADR-0005), in the same shape. The host adds the package and calls
  `AddCredProxLoginExchange()`; configuration is unchanged (`Type: LoginExchange`), and a
  credential naming `Type: LoginExchange` without the package fails startup naming the
  package to add. The exchange semantics carry across unchanged — per-request template
  expansion through the core's shared §3.2 expander, the token cached per
  `(credential, partition)`, and failures that never name secret values or response
  bodies.
- The `CredProx.OAuth` package [Experimental]: the three OAuth-based credential types —
  `OAuthClientCredentials`, `TokenExchange` and `JwtAssertion` — with their options,
  validators and token clients move out of the core into an add-on (ADR-0005), in the
  same shape. The host adds the package and calls `AddCredProxOAuth()`; configuration is
  unchanged (the same `Type` values), and a credential naming one of these types without
  the package fails startup naming the package to add. The
  `Microsoft.IdentityModel.Protocols.OpenIdConnect` dependency travels with the package,
  so a host that does not use the OAuth types no longer carries it; the in-memory token
  cache stays in the core, as ADR-0005 records.
- The `CredProx.Operations` package [Experimental]: the outbound throttle, the
  resilience adapter and the credential health probes move out of the core into an
  add-on (ADR-0005), in the same shape. The host adds the package and calls
  `AddCredProxThrottling()`, `AddCredProxResilience()` and
  `AddCredProxHealthProbes()`; configuration is unchanged
  (`CredProx:Throttling`, `CredProx:Resilience`, `CredProx:Health`), and a configured
  section whose feature is not registered fails startup naming the package to add — a
  written limit never sits inert. The pipeline placement is unchanged: resilience
  (Order 0) innermost inside one throttle permit (Order 10), both after signing. The
  `Microsoft.Extensions.Http.Resilience` and `Microsoft.Extensions.Diagnostics.HealthChecks`
  dependencies travel with the package; caller budgets and the kill switch stay core
  caller policy, on the `FixedWindowRateLimiter` the throttle now shares.
- `CredProxConfigValidation.RejectUnknownKeysAtStartup` [Experimental]: the fail-closed
  unknown-key rule (M17, §3.3) for an add-on package that owns a top-level `CredProx:*`
  section — allowed keys come from the package's options type by reflection, and an
  unknown key refuses startup exactly like a core section does. The three operations
  registration methods call it for `CredProx:Throttling`, `CredProx:Resilience` and
  `CredProx:Health`.
- `SecretValues.ResolveIfReferenceAsync` [Experimental]: the rule for an option value
  that is either a `secret:` reference or a literal is now a public seam — a reference
  resolves through the credential's scoped accessor, a literal passes through untouched —
  so an add-on credential type resolves its configured secret values through the same
  single core implementation the built-in types use instead of copying the rule.
- The caller-authenticator seam [Experimental]: `AddCredProxCallerAuthenticator<T>` lets
  your own code decide who a caller is, and CredProx applies the caller configuration —
  operation rules and header hygiene — around it.
- `AddCredProxCallerPolicy` [Experimental]: registers the `CredProx.Caller` authorization
  policy for middleware-enforcing hosts, naming every registered caller scheme — the
  built-in caller-key (and, when installed, caller-token) schemes and any caller
  authenticator you registered.
- `CredProxProblemResponses` [Experimental]: the problem-shaped refusals CredProx answers
  with (unknown caller, over-budget, refused destination, …) as callable helpers, so your
  own pipeline stages answer in the same shape the proxy uses.
- `HeaderHygieneFeature` now has a public constructor `(CredProxCoreOptions,
  IConfiguration)`, so a host can construct the header-hygiene stage directly; the
  feature registration path is unchanged.
- The caller-registry contributor seam [Experimental]: `ICallerRegistryContributor` lets a
  package build its derived data about the caller registry inside the very bind that
  accepted it — once at host start and once at every accepted live rebind — and commit it
  together with the registry as one `CallerRegistryGeneration`, swapped atomically. A
  contributor that fails refuses the bind exactly like a refused shape: startup fails, or
  the previous generation (registry and all committed data) keeps serving and one error
  line names the reason. Readers take `CallerRegistryProvider.CurrentGeneration` and get
  the registry and every contributor's data as one snapshot — derived data can never
  drift from, or be poisoned by, the configuration the registry was built against.
  Register with `AddCredProxCallerRegistryContributor<TContributor>`.
- The caller-registry validation seam [Experimental]: `ICallerRegistryValidator` lets a
  package — or your own host code — contribute rules about `CredProx:Callers` that the
  core must not learn, and CredProx runs every registered validator over the complete
  caller registry at host start AND on every live configuration rebind: a refused start
  stops the host, a refused live edit never takes effect — the previous registry keeps
  serving and the validator's reason is logged. Register with
  `AddCredProxCallerRegistryValidator<TValidator>`.
- The `CredProx.CallerTokens` package [Experimental]: agent tokens (M39, ADR-0004) move
  out of the core into their own package, so a host that authenticates callers with API
  keys alone no longer carries the JWT bearer handler. Same configuration keys
  (`CredProx:CallerToken`, `CredProx:Callers:<id>:TokenClientIds`), same scheme name, same
  guarantees; the host adds a package reference — the registration call
  `AddCredProxCallerTokenAuthentication` is unchanged.
- The `CredProx.CallerKeys` package [Experimental]: caller API keys (M6) move out of the
  core into their own package, so a host that authenticates callers with tokens alone no
  longer carries the key layer. Same configuration keys (`CredProx:CallerAuth`,
  `CredProx:Callers:<id>:Keys`), same scheme name, same guarantees; the host adds a
  package reference — the registration call `AddCredProxCallerAuthentication` is
  unchanged.
- `CredProx:CallerToken:RequireHttpsMetadata` [Experimental]: the https requirement on the
  authority's published metadata is now a configuration key — `true` by default, the
  production setting, because a caller-token path that accepts http metadata accepts a
  forged key set — so an offline run can point at a plain-http issuer stub from its
  environment config file instead of mutating the bearer options in host code. The
  opt-out is fail-closed: `false` is accepted only when `Authority` is http on a loopback
  host (`localhost`, `127.0.0.1`, `::1`); any other `Authority` combined with `false`
  refuses startup naming both keys, so a copied dev setting cannot quietly disable
  https metadata in production.
- `AddCredProx(IConfiguration)` [Experimental]: the one core registration — the token
  cache, the configuration secret stack, the built-in `StaticKey` credential type and the
  credential binder in a single idempotent call. A host then adds only its package calls
  (`AddCredProxCallerTokenAuthentication`, `AddCredProxOAuth`, …); the granular core calls
  stay public for hosts that want control, and the audit log stays the explicit
  `AddCredProxAudit` it has always been.

### Changed

- A caller identity that authenticates but is not among the configured callers is now
  refused with 401: a credential is honoured only for a caller you configured.
- Registering a caller authenticator while no caller is configured under
  `CredProx:Callers` now refuses to start, instead of quietly refusing every request.
- `CredProx` no longer depends on `Microsoft.AspNetCore.Authentication.JwtBearer`; the
  caller-token package does.
- HMAC body signing handles streamed bodies on the forwarder path: the size cap is decided
  by bytes the signing stage counted itself — a body exactly at the cap is forwarded whole
  with its measured length and signature, and 413 `credprox.body_too_large_to_sign` answers
  only a measured overrun, which is never signed or forwarded. Other body-read failures
  keep their own cause instead of being reported as a size cap.
- Caller keys are now served as one accepted unit with the caller registry, not as a
  lazily-rebuilt table. The `CredProx.CallerKeys` hashed key table is built eagerly inside
  the bind that accepted the registry — at host start and at every accepted live rebind —
  through the contributor seam above, and committed with the registry as one generation.
  A key whose `secret:` reference cannot be resolved no longer keeps a stale table
  serving quietly: it refuses host start, and refuses a live rebind — the previous
  registry and table keep serving — with one error line naming caller and key.
  `ConfigCallerStore` is now constructed from `CallerRegistryProvider` and `TimeProvider`:
  it reads no configuration and resolves no secret on the request path.
  `CallerRegistryProvider` now also rebinds on a configuration reload, not only when the
  secret source signals a change (the pre-existing constructor keeps its former trigger
  set). Malformed `KeyHash` declarations are part of the aggregated
  `OptionsValidationException` that names them at startup; resolving a `secret:`
  reference is the table contributor's alone (once per bind), so a reference that cannot
  resolve refuses the bind there instead — startup fails, or the previous generation
  keeps serving.

- One observed change performs exactly one caller-registry bind ATTEMPT in the default
  callback order; a host that registers its own reload callback on the shared
  configuration before the source's callback measures two binds for that reload — both
  safe, no signal dropped. The provider no longer double-watches the common host: the built-in `ConfigurationSecretSource` fires
  its own change token on every reload of its configuration root, so when the source is
  that source over the watched root, the provider watches that token alone — one reload,
  one trigger. Where a host's source is not backed by the watched configuration, both
  watches stay registered and a trigger whose inputs match the last bind attempt's is
  dropped with one debug line, where it used to bind again. A refused reload therefore
  writes one error line per attempt and an accepted one resolves each contributed secret
  exactly once; in a both-watches host a reload that changes nothing the caller registry
  reads logs no rebind, while in the single-watch host every reload is a source signal —
  the provider cannot tell a no-op reload from a rotated secret, and one honest bind per
  reload is the promise. A genuine change — a `CredProx:Callers` value, or a fresh
  secret-source signal — always rebinds: a transient bind failure recovers on the next
  signal even though configuration is unchanged, and a rotated secret rebinds even though
  no configuration value moved.
- Secret-resolution failures name the reference or key and the source exception's TYPE,
  never the source's own message: an unresolvable `secret:` reference now reads
  `could not be resolved (source exception <Type>)`, and a caller key's `secret:`
  `KeyHash` likewise. A throwing secret source can no longer carry its message text —
  which can quote a value — into user-visible startup or rebind errors.
- `secret:` references in a `KeyHash` are checked by shape at validation and resolved
  once per bind, not resolved twice. The contributed key rules now accept any
  non-empty `secret:` reference unseen — a bare `secret:` is refused as an empty
  reference — and the eager table contributor is the sole resolver: each declared secret
  is read exactly once per bind, and a reference that resolves to something other than a
  `sha256:<hex>` hash still refuses the same bind.
- `ICallerRegistryContributor.Contribute` [Experimental, unreleased] no longer takes a
  `CancellationToken`: the core runs the build inside the bind, which runs inside a
  configuration-change callback — nothing there is cancellable, so the contract is
  plainly synchronous.

### Breaking

- The `Hmac` and `LoginExchange` credential types are no longer part of the `CredProx`
  package (ADR-0005). Removed from it: `HmacOptions`, `HmacAlgorithm`,
  `HmacSignatureEncoding`, `HmacTimestampFormat`, `HmacProvider`, `HmacSignFeature`,
  `LoginExchangeOptions`, `LoginExchangeCredentials`, `LoginExchangeResponse` and
  `LoginExchangeProvider`. Replacements: add the `CredProx.Hmac` /
  `CredProx.LoginExchange` package reference and call `AddCredProxHmac()` /
  `AddCredProxLoginExchange()`; the types are unchanged there, the configuration keys
  and the `Type` discriminator are unchanged, and the credential types resolve through
  the same public registration seam any third-party type uses. Hosts that do not add a
  package keep working — a credential naming the packaged type without it fails startup
  naming the package to add.
- The `OAuthClientCredentials`, `TokenExchange` and `JwtAssertion` credential types are
  no longer part of the `CredProx` package (ADR-0005). Removed from it:
  `OAuthClientCredentialsProvider`, `OAuthClientCredentialsOptions`,
  `OAuthClientAuthentication`, `TokenExchangeProvider`, `TokenExchangeOptions`,
  `TokenExchangeMode`, `JwtAssertionProvider`, `JwtAssertionOptions`,
  `JwtAssertionAlgorithm` and `JwtAssertionExchange`. Replacements: add the
  `CredProx.OAuth` package reference and call `AddCredProxOAuth()`; the types are
  unchanged there (namespaces included), the configuration keys and the `Type`
  discriminators are unchanged, and `IRequiresInboundToken` — implemented by
  `TokenExchangeOptions` — stays in the core. Hosts that do not add the package keep
  working — a credential naming one of these types without it fails startup naming the
  package to add. This is binary-breaking for the moved types (different assembly);
  recompile against both packages.
- The outbound throttle, the resilience adapter and the credential health probes are
  no longer part of the `CredProx` package (ADR-0005). Removed from it:
  `ThrottleOptions`, `ThrottleClusterOptions`, `ResilienceOptions`,
  `ResilienceClusterOptions`, `CredProxHealthOptions`, `AddCredProxThrottling`,
  `AddCredProxResilience` and `AddCredProxHealthProbes`. Replacements: add the
  `CredProx.Operations` package reference and call the same-named `Add` methods; the
  configuration sections, options shapes and problem responses are unchanged there, and
  a configured section whose feature is not registered fails startup naming the package
  to add. `FixedWindowRateLimiter` stays in the core — caller budgets are core policy —
  and is now the public limiter the Operations throttle uses. A host that configures
  `CredProx:Throttling`, `CredProx:Resilience` or `CredProx:Health` without the package
  now fails startup instead of ignoring the section. This is binary-breaking for the
  moved types (different assembly); recompile against both packages.
- The caller-key types now live in `CredProx.CallerKeys` instead of `CredProx`
  (namespaces unchanged): `AddCredProxCallerAuthentication`, `CallerKeyOptions`,
  `ICallerStore`, `CallerKeyMatch`, `ConfigCallerStore` and the request-path handler
  `CallerKeyAuthenticationHandler`. The public `CallerKey` model type
  is removed outright rather than moved — a key entry is configuration the package
  validates, and its hash material never leaves the store. The `CallerBinder` two-argument
  constructor (`configuration`, `accessorFactory`) is collapsed into the one constructor
  that also takes contributed rules; pass an empty rule list where you passed none. The
  `HeaderHygieneFeature` constructor taking `IEnumerable<CallerKeyOptions>` is replaced by
  the `(CredProxCoreOptions, IConfiguration)` one named under Added. This
  is binary-breaking for the removed members (pre-1.0 experimental surface); recompile.
  The scheme name's
  public constant is now `CallerKeyOptions.Scheme` (same value) and
  `CredProxAuth.CallerKeyScheme` is no longer public. `CallerDefinition` no longer
  carries `Keys` — the keys package reads that key from configuration itself, and
  entry-shape validation (missing or double-listed `KeyId`, malformed `KeyHash`,
  unparseable `ExpiresAt`, unknown fields under a `Keys` entry) rides the
  caller-registry validation seam: host start AND every live rebind, a refused rebind
  keeping the previous registry serving, with the same verbatim error messages as
  before the split. Without the package the entries are inert — no key can authenticate
  and nothing validates them. This is binary-breaking for the moved types (different
  assembly); recompile against both packages.
- The caller-token types now live in `CredProx.CallerTokens` instead of `CredProx`
  (namespaces unchanged): `AddCredProxCallerTokenAuthentication`, `CallerTokenOptions`,
  `ICallerTokenMapper`, `CallerTokenMapping`, `DefaultCallerTokenMapper`. The scheme name's
  public constant is now `CallerTokenOptions.Scheme` (same value) and
  `CredProxAuth.CallerTokenScheme` is no longer public. `CallerDefinition` no longer
  carries `TokenClientIds` — the token package reads that key from configuration itself,
  and entry-shape validation (blank, padded or double-listed client ids) rides the
  caller-registry validation seam above: host start AND every live rebind, a refused
  rebind keeping the previous registry serving. The same config was already refused
  before the split — at the registration call rather than at host start — so the visible
  change is timing, plus the rebind guarantee a registration-time check could never have:
  drift into a refused shape after start is refused too. (Consequence: a host that
  registers the services but never starts the host is no longer refused at registration.)
  Without the package the entries are inert — no client id can authenticate and nothing
  validates them. This is binary-breaking for the moved types (different assembly);
  recompile against both packages.

### Fixed
- A caller whose request waits out a vendor pause is now forwarded once the pause ends, even
  when the wait timer wakes a fraction of a millisecond early; such a request used to be
  answered `429 credprox.throttled` for a cluster that had just become ready. A pause - or an
  extension of it that arrives while the request waits - that outlasts `MaxQueueWait` still
  answers `429`.

## [0.11.0] - 2026-11-16

Agent tokens (M39): an agent presents a short-lived Microsoft Entra (or any OIDC) access
token instead of a stored secret, and Entra app roles narrow it to named rules — a token
gets exactly the operations its roles name, and a caller without named rules admits no
token. The documentation leads with the most useful examples and the Spotify example is
removed (M40). Minor bump: the caller-token API is additive and the release carries one
Breaking change — the caller contract surface (`CallerDefinition`, `CallerOperationRule`,
`CallerIdentity`) collapses to single constructors with optional parameters; migration is
a recompile, and existing positional call sites need no edits, except that deconstructing a
`CallerIdentity` now takes three variables (see Breaking).

### Added

- Caller tokens for agents (M39, ADR-0004; sample E19 `samples/AgentTokens`):
  `services.AddCredProxCallerTokenAuthentication(configuration)` registers a stock JWT
  bearer scheme (`CredProxAuth.CallerTokenScheme`) that validates short-lived Entra / OIDC
  access tokens, configured under `CredProx:CallerToken` (`Authority`, `Audience`, optional
  `MaxTokenAge`). A caller accepts tokens from the clients listed in its new
  `TokenClientIds`; operation rules gain an optional `Name`, and a token gets exactly the
  operations whose names appear in its `roles`/`scp`. New public types:
  `CallerTokenOptions`, `ICallerTokenMapper` with `DefaultCallerTokenMapper`,
  `CallerTokenMapping`, `CallerRequestScopes`, and `CallerIdentity.ClientId`. Caller API
  keys keep working unchanged; a request may use either.
- Caller-token handler swap point (M39, ADR-0004):
  `AddCredProxCallerTokenAuthentication` takes an optional `registerScheme` callback.
  When supplied it runs instead of the stock JWT bearer registration, so a host can
  register its own validation handler under `CredProxAuth.CallerTokenScheme`
  (`Microsoft.Identity.Web`, another OIDC issuer, an introspection handler) without the
  scheme-collision throw and without leaving `CallerTokenOptions` unregistered; the
  required `Authority`/`Audience` checks apply to the default path only, and
  `MaxTokenAge` still binds in both. A host that only tunes the stock handler uses the
  standard `PostConfigure<JwtBearerOptions>(CredProxAuth.CallerTokenScheme, …)`.
- Caller-token authentication claim-shape disclosure (M39, ADR-0004): the caller-token
  scheme sets `MapInboundClaims = false`, so a caller token's claims reach the mapper and
  the host's `HttpContext.User` under Entra's raw names — `roles`, `scp`, `azp`, `appid`,
  `uti` — and the stock JWT bearer rename to the long claim types never happens on this
  scheme. `RoleClaimType` is pinned to the raw `roles`, so `ClaimsPrincipal.IsInRole`
  keeps working for hosts on the token path. The claim names are configuration, not
  code: `CallerTokenOptions.ClientClaimNames` (default `azp`, `appid`) and
  `CallerTokenOptions.ScopeClaimNames` (default `roles`, `scp`) let an OIDC issuer that
  names the client id or the scopes differently be met by configuration.

### Changed

- Caller tokens require named rules: a token gets exactly the operations its roles name;
  a caller without named rules admits no token (M39, ADR-0004). The token's scope set
  intersects the caller's operation rules through the rule `Name` only: an unnamed rule
  admits no token (it stays a caller-key-path rule), a token whose roles name no rule
  gets nothing, a token carrying no roles at all is denied, and a caller that declares no
  operation rules denies every token request — all with the existing
  `403 credprox.operation_not_allowed`. The caller-key path is byte-for-byte unchanged:
  an empty allow-list there is still opt-out.
- `CredProx:CallerToken:MaxTokenAge` (M39) is now enforced by the CredProx caller-
  authentication stage before any `ICallerTokenMapper` runs, so replacing the mapper
  cannot drop the bound; an `iat` more than the JWT bearer handler's default five-minute
  clock skew in the future is rejected as well. The value must be greater than zero and
  less than 24 h — anything else now refuses startup — and is written `d.HH:mm:ss`: a
  bare number binds as days (`15` is fifteen days; fifteen minutes is `00:15:00`). It is
  read once at startup; changing it requires a restart.
- Diagnosability of refused caller tokens (M39): the authentication and operation stages
  log the refusal reason server-side (stale token, unlisted client, no matching named
  rule); response bodies are unchanged. A caller that lists `TokenClientIds` but names no
  operation rule logs one startup warning naming it ("this caller can never admit a
  token") — the host starts and its caller-key path keeps working.
- Configuration hardening (M39): an `Operations:N:Name` with leading or trailing
  whitespace is refused at startup naming the caller and rule index, like padded
  `TokenClientIds` entries already were, instead of binding and matching nothing.

### Breaking

- The caller contract surface collapses to single constructors with optional parameters
  (M39; pre-1.0, no released consumer is affected). Removed: `CallerDefinition`'s
  four-argument constructor `(String, IReadOnlyList<CallerKey>,
  IReadOnlyList<CallerOperationRule>, CallerLimits)`, `CallerOperationRule`'s
  three-argument constructor `(String, IReadOnlyCollection<String>,
  IReadOnlyCollection<String>)`, `CallerIdentity`'s two-argument constructor
  `(String, String)` and its two-argument `Deconstruct`. Replacements:
  `CallerDefinition(callerId, keys, operations, limits = null, tokenClientIds = null)`,
  `CallerOperationRule(route, methods, pathPatterns, name = null)`, and the positional
  record `CallerIdentity(CallerId, KeyId, ClientId = null)`. Migration: recompile against
  this package — existing positional call sites are source-compatible and need no
  edits; deconstruct with three variables
  (`var (callerId, keyId, clientId) = identity;`) or read the properties.

## [0.10.0] - 2026-11-15

Token lifetime policy unified across all three credential providers (M38): every
vendor-stated expiry (`expires_in`, `expires_at`) now follows the same accept, cap
and reject rules on `OAuthClientCredentials`, `TokenExchange` and `JwtAssertion`,
each with once-per-credential notices. The only public surface change is the
additive optional-`ILogger` constructor overloads on `TokenExchangeProvider` and
`JwtAssertionProvider`; no existing API changed.

### Added

- `TokenExchangeProvider` and `JwtAssertionProvider` gained additive constructor
  overloads with an optional `ILogger<T>` parameter (M38), used for the once-per-credential
  lifetime notices. The existing constructors are unchanged, and hosts with no logging
  registered build and run the providers exactly as before.

### Changed

- Token lifetime policy, outcome A (M38): `TokenExchange` and `JwtAssertion` now reject
  a non-finite or thousands-grouped `expires_in` through the protocol-violation path,
  the same rule the OAuth client-credentials provider has since 0.9.4 (M37 A1): nothing
  is cached, the error names the field and the credential id, never the value or the
  token. `JwtAssertion` keeps its documented precedence — an unusable `expires_in`
  still gives way to a valid `expires_at`, and only rejects when nothing usable
  remains. Zero, absent and JSON-null values keep the `DefaultLifetime` fallback on
  all three providers, unchanged. No public API change.
- Token lifetime policy, outcome B (M38): all three providers (`OAuthClientCredentials`,
  `TokenExchange`, `JwtAssertion`) now also reject a non-empty, non-numeric `expires_in`
  string (`"abc"`, `"0x10"`, non-ASCII digits) through the same protocol-violation path —
  nothing cached, the error names the field and the credential id, never the value. The
  empty string `""` means "no stated expiry": it keeps the `DefaultLifetime`/precedence
  fallback but now logs one warning per credential, mirroring the existing zero-lifetime
  notice. `TokenExchangeProvider` and `JwtAssertionProvider` gain optional-`ILogger`
  constructor overloads for these notices (additive; the existing constructors are
  unchanged). `JwtAssertion`'s rejection message now reads "an invalid `expires_in`
  value", covering all rejected shapes.
- Token lifetime policy, outcome C (M38): an accepted vendor lifetime above 24 hours is now
  capped to 24 hours on all three providers, with one warning per credential. Values too
  large for a `TimeSpan` (`1e12`, `1e300`) are capped too — they previously surfaced as a
  generic "malformed response" error through the overflow path; they now cache normally on
  the capped clock. `JwtAssertion`'s cap rides after its documented precedence, so a
  far-future `expires_at` is capped to now + 24 hours as well. The cap applies only to
  vendor-supplied lifetimes — the configured `DefaultLifetime` is never capped. No new
  option; no public API change.
- Token lifetime policy, outcome D (M38): `JwtAssertion`'s `expires_at` is now read with an
  invariant ISO-8601 grammar instead of the host culture: an offset-less value means UTC,
  not host-local wall time (a non-UTC host previously shifted the cached expiry by its UTC
  offset), and host-culture dotted formats like `"15.11.2026 22:00:00"` are no longer
  accepted — they now fall back with a warning, as unparseable values always should have.
  A JSON-number `expires_at` is accepted as epoch seconds (GitHub-App-style responses emit
  it). Absent and JSON-null keep the silent fallback. Values that already carry an
  explicit offset or the UTC designator `Z` — the shape the shipped GitHub App and Azure
  Container Apps samples emit — are read exactly as before. No public API change.
- Token lifetime policy, past expiry (M38): `JwtAssertion` now treats an `expires_at` that is
  already at or before the current time as unusable — the same class as a negative
  `expires_in` — whether ISO text or epoch seconds (`0` and exactly-now included). When the
  response states no other usable expiry, it is rejected through the protocol-violation
  path: nothing is cached, the error names the field and the credential id, never the
  value. A usable `expires_in` still wins the documented precedence, and a future
  `expires_at` is unaffected. No public API change.
- The benchmark regression gate (`scripts/bench-compare.sh`): the two Overhead-suite
  SSE arms (`SsePlain`, `SseCredProx`) now WARN above the +12% allocation allowance
  instead of failing, and hard-FAIL only above 2.5× the baseline allocation
  (per-arm `GROSS_ALLOC_FAIL_MULT`, keyed by exact `(suite, method)` pair). The
  interleaved A/B attribution of 2026-11-15 showed the released 0.9.4 code failing
  its own +12% FAIL at the same rate as the candidate — 2 of 3 quiet-gated passes
  each, with no changed code in the arm's path — so that FAIL could not identify a
  code change; a gross regression (2.5× and above) still fails. Every other arm is
  unchanged. Evidence: `docs/benchmarks.md`. No library change.

## [0.9.4] - 2026-11-15

Library hardening (M37) only — the vendor `expires_in` is parsed with the canonical
JSON-number grammar on all three credential providers. Negative values reject through
the protocol-violation path on all three; non-finite and thousands-grouped values
reject on the OAuth client-credentials provider, while the other two providers keep
the `DefaultLifetime` fallback, pending the lifetime-policy decision. Nothing is
cached on any rejection; no public API change (`src/` additions are internal types).

### Changed

- The benchmark regression gate (`scripts/bench-compare.sh`) hardened (M37):
  a new-run arm with `Statistics.N` below `N_FLOOR` (10) warns and every `ok`
  line prints N and P95; `[Params]` rows keep `Parameters` in the comparison
  key and a row duplicated in title AND parameters FAILs; a `RATIO-SKIPPED`
  arm counts (FAIL in fail-mode suites, WARN in warn-mode ones) so the summary
  never reads clean while a timing gate sat out; `ALLOW_PARTIAL=1` with zero
  methods compared FAILs; inverted `RATIO_WARN`/`RATIO_FAIL` refuses to start
  (exit 2). The SSE workload now measures real per-event redaction over a
  bounded three-event stream, the Overhead baseline was re-captured for it,
  and the SSE allocation allowance is re-ruled 8% → 12% on a measured six-pass
  band: max upward excursion over the reference is +1,520 B (10.5%), so 12%
  covers the noise and misses no regression above +1,736 B on the SSE arms
  (`docs/benchmarks.md`, `baselines/0.9.3/MACHINE.md`).
- `TokenExchangeProvider` and `JwtAssertionProvider` now reject a negative `expires_in` — the caller gets `credprox.credential_unavailable` and nothing is cached, where a `DefaultLifetime` token was cached before (see the Fixed entry for the full contract, including the `expires_at` precedence `JwtAssertionProvider` keeps).

### Fixed

- `OAuthClientCredentialsProvider` now rejects a token response whose `expires_in`
  is a non-finite numeric string (`"Infinity"`, `"-Infinity"`, `"NaN"`) or
  thousands-grouped (`"1,000"`). The old `double.TryParse` overload accepted
  `Infinity`/`-Infinity` only under the invariant culture (an
  InvariantGlobalization host); under ICU cultures the non-finite symbol is
  `∞`, so those two names do not parse there (`NaN` parses under several ICU
  cultures), while exponent overflow (`"1e400"` = +∞) arrives the same way on
  every host. Whatever did parse as non-finite fell silently through to
  `DefaultLifetime` — a token minted from a nonsense expiry was cached and
  served for a full hour. Rejection
  follows the M33 negative-`expires_in` protocol-violation path: nothing cached,
  `credprox.credential_unavailable`, and a message naming the field and the
  credential id, never the value or the token. String `expires_in` now parses
  with the canonical JSON-number grammar (`NumberStyles.Float`,
  `CultureInfo.InvariantCulture`) instead of the machine's current culture with
  thousands grouping. Grouped digits are rejected deliberately: `expires_in` is
  a JSON number, and a grouped string parses only under some cultures — accepting
  it would make the cached token lifetime depend on the machine's current
  culture, and rejecting a value that is unmistakably a malformed number is the
  safer default over a silent fallback. The `expires_in: 0` one-warning
  `DefaultLifetime` fallback is unchanged.
- `TokenExchangeProvider` and `JwtAssertionProvider` parse a string `expires_in`
  with the canonical JSON-number grammar (`NumberStyles.Float`,
  `CultureInfo.InvariantCulture`), as the OAuth provider now does: on a
  decimal-comma host `"3600.9"` cached a ~10-hour lifetime (and `"1,000"`
  collapsed to one second), so the cached token lifetime no longer depends on
  the machine's current culture. Both also reject a negative `expires_in`
  through the M33 protocol-violation path — nothing cached, the message naming
  the field and the credential id, never the value or the token. The ordering
  differs where an absolute expiry exists: `TokenExchangeProvider` has no
  absolute-expiry field, so a negative `expires_in` always rejects;
  `JwtAssertionProvider` treats it as unusable rather than an instant throw — a
  valid `ExpiresAtField` keeps precedence, and only a negative value with no
  usable `expires_at` rejects. Zero stays its own unchanged branch in both:
  never rejected, falling back to `DefaultLifetime` (and, in
  `JwtAssertionProvider`, to a valid `expires_at` first).

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
