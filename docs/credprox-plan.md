# CredProx — plan for the first public release (0.3 scope)

> **CredProx**: outbound credential and policy brokering for third-party APIs, built on YARP.
> Callers send requests without secrets. CredProx attaches the right credential, enforces the
> right policy, and forwards the request.

Status: proposal · Source POC: the YARP extensions in `CoreApi/Yarp` and `CoreApi/Domain` of
`yarp-proxy-custom-extensions` (`CoreFuncs`, `AppHost` and `ServiceDefaults` are out of scope).

**Release strategy.** The earlier draft staged the work as 0.1 → 0.2 → 0.3. This plan goes
straight to the **0.3 feature set** for the first public release: the credential core, least
privilege and operations features, traffic shaping, more credential types, and the plugin
architecture with vendor presets and a testing kit. The three phases are kept as internal
milestones, each published as a preview to the Gitea package registry so the work gets used
before the public release (see §7).

---

## 1. Why this is worth releasing

This repo shows a pattern that keeps coming up in practice. Data pipelines, internal services and
increasingly AI agents need to call third-party APIs (ADP, Cayuse, Salesforce, Workday, ...). Each
vendor authenticates differently: OAuth client credentials, Basic-to-token exchange, client
certificates (mTLS), HMAC signatures. Today every consumer re-implements that logic and holds the
secrets.

A proxy that **brokers credentials on egress** gives you:
- Secrets live in one place (Key Vault or similar), never in consumers.
- One token cache per vendor instead of one per consumer, so fewer token calls and fewer
  rate-limit hits.
- Vendor quirks (environment hostnames, cert rotation, token lifetimes) are fixed once.
- One place for audit, throttling and least-privilege policy.

### Landscape

| Option | What it covers | Gap CredProx fills |
|---|---|---|
| YARP (`Yarp.ReverseProxy`) | Routing, transforms, health, LB, inbound rate limits / output cache / timeouts per route | No outbound-credential features; you hand-write transforms |
| Duende BFF (`Duende.Bff.Yarp`) | User/client token attachment on YARP routes | Built for the browser-BFF pattern, OIDC-centric, commercially licensed for most orgs. No mTLS-per-cluster, vendor login flows, HMAC, etc. |
| Duende.AccessTokenManagement | Client-credentials token caching for `HttpClient` | Not YARP-aware. CredProx can **use it as an optional token backend** rather than compete |
| Linbik.YARP | Per-service JWT injection, refresh tokens | Narrow (OAuth authorization-code / user tokens), thin docs |
| MuleSoft / Gravitee / Permit.io / agentgateway | Outbound OAuth / OBO / credential injection policies, agent egress brokering | Commercial gateway products, not an embeddable .NET library |

The commercial gateways ship "credential injection" and "credential brokering for AI agents"
as headline features (2025–2026). That shows real demand. Nothing open-source and embeddable
fills this space for .NET/YARP.

### Name

**CredProx**, short for credential proxy. "Cred" covers every credential type the library
handles (tokens, keys, certificates, signatures, logins), not just keys. Packages: `CredProx`
(core), `CredProx.AzureKeyVault`, and later `CredProx.Aws`, `CredProx.Duende`. Config section
`"CredProx"`, metadata keys `CredProx.*`.

Checked 2026-10-13: no NuGet package with this id, and no software product found by web search.
A trademark search has not been done. In physical security, "prox" also means proximity cards,
so the package description and tags (`yarp`, `reverse-proxy`, `oauth`, `credentials`) should make
the .NET context obvious.
The name deliberately avoids a `Yarp.` prefix: YARP is a Microsoft project, and a `Yarp.*` id
would read as official (and may conflict with prefix reservation).

Alternatives considered: *KeyProx* (rejected: Honeywell sells a "KeyProx" alarm keypad),
*KeyRelay*, *Proxeal*, *Proxenia*, *Attaché*.

---

## 2. Current-state findings (from the POC review)

These must be fixed or designed out in phase A:

| # | Finding | Location | Resolution |
|---|---|---|---|
| F1 | Failed token fetch is cached **with no expiry**, so one transient failure gives permanent 401s | `Context.cs` `GetAuthTokenAsync` | New token cache: negative TTL, single-flight, early refresh |
| F2 | `ITransformHandler` registered by **route id**, resolved by **cluster id** | `Abstractions.cs` / `Forwarder.cs` | Credentials bound to routes, connection settings bound to clusters, keyed explicitly |
| F3 | Client certs held in static dictionaries, never reloaded | `Context.cs` | `ISecretSource` with change tokens; rebuild client on rotation |
| F4 | `ITransformFactory` clashes with YARP's `Yarp.ReverseProxy.Transforms.Builder.ITransformFactory` | `Abstractions.cs` | Remove; use YARP's `ITransformProvider` |
| F5 | `ForwarderTransformHttpClientFactory` copies YARP's factory (~80 lines) | `Forwarder.cs` | Subclass `ForwarderHttpClientFactory` (public; `ConfigureHandler`/`WrapHandler` are virtual) |
| F6 | `X-API-Env` matched with `Mode: Contains`, then substituted into hostnames: a crafted header changes the host the proxy calls | `appsettings.json`, `cayuse.cs` | Destination templates accept **allow-listed values only**, as a library guarantee |
| F7 | Exception logged as `ex.InnerException` (loses the real error) | `Context.cs` | Fixed by rewrite |
| F8 | Heavy app-level deps (Web SDK, Azure.Identity, Microsoft.Identity.Web for cert loading) | `CoreApi.csproj` | Core depends only on `Yarp.ReverseProxy`; Azure in an add-on package |
| F9 | No tests, net9-only (support ends Nov 2026), no package metadata | — | See §5–§7 |

---

## 3. Architecture

### 3.1 Features and hooks

Every CredProx capability is a **feature**: a class that implements one or more of four hooks
YARP already exposes.

| Hook | YARP mechanism | Bound to |
|---|---|---|
| `IRequestFeature` | `ITransformProvider` → `AddRequestTransform` | Route |
| `IResponseFeature` | `ForwarderHttpClientFactory.WrapHandler` — a dispatcher at the end of the outbound pipeline, running the settled upstream response through the features **before YARP copies any byte to the caller** (a YARP response transform is too late: the headers are already copied by then — proved in M20) | Per proxied request |
| `IConnectionFeature` | `ForwarderHttpClientFactory.ConfigureHandler` | Cluster |
| `IPipelineFeature` | `ForwarderHttpClientFactory.WrapHandler` (`DelegatingHandler`) | Cluster |

Built-in features and user-written features register the same way, so the library stays small and
users can extend it without forking.

### 3.2 Configuration

YARP route/cluster `Metadata` is `Dictionary<string,string>`, which is flat and not suited to
structured options. So structured config lives in a `CredProx` section, and YARP metadata only
**references** it by name:

```jsonc
{
  "ReverseProxy": {
    "Routes": {
      "adp": {
        "ClusterId": "adp",
        "Match": { "Path": "/adp/{**catch-all}" },
        "Transforms": [{ "PathRemovePrefix": "/adp" }],
        "Metadata": { "CredProx.Credential": "adp" }
      },
      "cayuse": {
        "ClusterId": "cayuse",
        "Match": { "Path": "/cayuse/{**catch-all}" },
        "Metadata": { "CredProx.Credential": "cayuse", "CredProx.Destination": "cayuse" }
      }
    },
    "Clusters": {
      "adp":    { "Destinations": { "d1": { "Address": "https://api.adp.com" } },
                  "Metadata": { "CredProx.Connection": "adp" } },
      "cayuse": { "Destinations": { "d1": { "Address": "https://placeholder.invalid" } } }
    }
  },
  "CredProx": {
    "Credentials": {
      "adp": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "https://accounts.adp.com/auth/oauth/v2/token",
        "ClientAuthentication": "BasicHeader",
        "ClientId": "secret:adp-client-id",
        "ClientSecret": "secret:adp-client-secret",
        "Connection": "adp"                       // token call also uses the mTLS cert
      },
      "cayuse": {
        "Type": "LoginExchange",
        "Partition": { "From": "header:X-API-Env", "Allowed": ["uat", "app"] },
        "LoginEndpoint": "https://signin.{partition}.cayuse.com/basicauth?tenant_id={secret:cayuse-{partition}-tenantid}",
        "Method": "GET",
        "Basic": { "User": "secret:cayuse-{partition}-user", "Password": "secret:cayuse-{partition}-pass" },
        "Response": "RawBody",
        "Lifetime": "00:55:00"
      }
    },
    "Destinations": {
      "cayuse": { "Template": "https://target.{partition}.cayuse.com", "Partition": "header:X-API-Env",
                  "Allowed": ["uat", "app"], "StripHeader": true }
    },
    "Connections": {
      "adp": { "ClientCertificate": "secret:adp-auth-cert" }
    },
    "InboundKeyHeader": "X-API-Key"            // always stripped before forwarding
  }
}
```

The ADP and Cayuse integrations become **pure configuration**. No vendor C# code remains.

### 3.3 Core components

- **`ISecretSource`**: resolves `secret:<name>` references. Core ships `ConfigurationSecretSource`
  (covers env vars, user-secrets, and Key Vault via the existing config provider) with change-token
  reload. `CredProx.AzureKeyVault` adds a direct `SecretClient` source with tag filtering (the
  current `PrefixKeyVaultSecretManager` behaviour).
- **`ITokenCache`**: keyed by `(credential, partition)`. Behaviour:
  single-flight per key (concurrent requests share one fetch), refresh at 80% of lifetime or
  `expires_in − skew`, **negative cache of ~5–30 s** on failure, `Invalidate(key)` for
  refresh-on-401. Default in-memory; interface allows a distributed implementation later.
- **`ICredentialProvider`**: produces what to attach (header, query, or signature) for a request.
  Built-in implementations are listed in §4.
- **`CredProxForwarderHttpClientFactory : ForwarderHttpClientFactory`**: applies
  `IConnectionFeature`s in `ConfigureHandler` and composes `IPipelineFeature`s in `WrapHandler`.
  Client certs are rebuilt when the secret changes. YARP recreates the client when
  `CanReuseOldClient` returns false, so a version stamp is added to that check.
- **Validation**: on startup, every `CredProx.*` metadata reference must resolve to a defined
  feature, and every `secret:` reference must resolve (optionally lazily, with a warning). Failures
  throw `OptionsValidationException`. Unknown keys under a credential section are rejected at bind
  time (startup and reload), naming the credential and key; the allowed keys are that type's
  options properties, derived by reflection, so plugin credential types declare their own keys (M16).
  The same rule covers the remaining sections (M17): `CredProx:Destinations` and
  `CredProx:Connections` reject unknown keys at startup and reload; `CredProx:Audit`,
  `CredProx:Health`, `CredProx:Throttling` and `CredProx:Resilience` reject them eagerly at
  startup (their options are one-shot); at the `CredProx` root a misspelled option or a whole
  section name is rejected, so a typo can never silently disable a feature. Cluster entries in
  the throttling/resilience dictionaries are checked against their options type; cluster names
  stay user-defined. List entries must be indexed (M18): a non-index child inside a scalar
  list (`Allowed:oops = prod`) or a block under an index is rejected like an unknown key,
  since the binder reads only indices there; and the kill-switch section (M18, §8.4) is
  guarded by the same rule — a switch silently unarmed by a typo is the failure it exists
  to prevent.
- **Diagnostics**: `ActivitySource` + `Meter` named `CredProx`. Counters for token fetch
  success/failure and cache hit/miss; histogram for token fetch latency. Never log secret values.

### 3.4 Failure semantics

| Situation | Response to caller | Notes |
|---|---|---|
| Credential cannot be obtained | `502` + `ProblemDetails` (`credprox.credential_unavailable`) | Not 401: the *caller* is authenticated, the *proxy* failed upstream. Request is not forwarded |
| Partition value not allowed | `400` (`credprox.partition_not_allowed`) | Never forwarded |
| Upstream returns 401 with a cached token | Invalidate, refetch, retry **once** (idempotent methods, or bodies ≤ buffer limit) | Configurable; off for non-idempotent by default |

Short-circuiting from a request transform will be covered by integration tests against YARP 2.3.
The POC sets `Response.StatusCode` and relies on YARP skipping the forward, which needs a test to confirm.

Additional failure responses (0.3 features and later additions, each row tagged):

| Situation | Response to caller |
|---|---|
| Missing or invalid inbound API key | `401` (`credprox.caller_unauthenticated`) |
| Caller not allowed this route / method / path | `403` (`credprox.operation_not_allowed`) |
| Outbound throttle queue full or wait exceeded | `429` with `Retry-After` (`credprox.throttled`) |
| Circuit open for a cluster | `503` (`credprox.upstream_unavailable`) |
| Upstream attempt timeout exhausted | `504` (`credprox.upstream_timeout`) |
| Body larger than the signing buffer limit | `413` (`credprox.body_too_large_to_sign`) |
| No inbound user token on a token-exchange route (M14) | `401` (`credprox.inbound_token_missing`) |
| Inbound user token fails validation (M14) | `401` (`credprox.inbound_token_invalid`) |
| Provider signals the user has not consented yet (M19) | `401` (`credprox.consent_required`; `authorize_url` extension member when the provider's URL is an absolute http(s) URL without credentials) — distinct from the generic 502: consent is a next step, not a broken credential |

### 3.5 Plugin architecture

The feature model in §3.1 is opened up as a deliberate, documented plugin contract. Every
built-in feature is written against the same public API that third parties use.

**Levels supported**

| Level | Mechanism | Status in 0.3 |
|---|---|---|
| Code plugins | Public interfaces registered explicitly in DI: `.AddCredProx().AddCredentialType<T, TOptions>("Name")` | Yes |
| Plugin packages | NuGet packages that register code plugins: `CredProx.AzureKeyVault`, `CredProx.Aws` (later), community packages | Yes |
| Config-only presets | A vendor preset is a JSON fragment (token endpoint, client auth style, lifetime defaults, required secrets) referenced by name: `"Preset": "acme-oauth"` | Yes |
| Runtime assembly loading | Drop-in DLLs via `AssemblyLoadContext` | **No.** Auto-loading code in a process that holds every secret is an attack surface |
| Out-of-process plugins | Webhooks, sidecars, WASM | **No.** Adds latency and moves secrets across a boundary |

**Plugin points**

| Plugin point | Interface | Built-ins in 0.3 |
|---|---|---|
| Credential type | `ICredentialProvider<TOptions>` | OAuthClientCredentials, LoginExchange, StaticKey, TokenCredential, JwtAssertion, Hmac |
| Secret source | `ISecretSource` | Configuration, Azure Key Vault |
| Partition source | `IPartitionSource` | `header:`, `claim:`, `caller:`, `route:` |
| Caller authentication | ASP.NET Core `AuthenticationHandler` + `ICallerStore` | API keys from config / secret source |
| Token cache backend | `ITokenCache` | In-memory |
| Request / response feature | `IRequestFeature` / `IResponseFeature` | Header hygiene, operation allow-lists; response secret scrubbing (M20, §8.2); vendor error normalisation (M24, §8.5) |
| Outbound pipeline | `IPipelineFeature` | Throttling, resilience, audit |
| Audit sink | `IAuditSink` | `ILogger`, OpenTelemetry logs |
| Health probe | `ICredentialHealthProbe` | Token fetch probe, certificate expiry probe |
| Preset source | `IPresetSource` | Presets from configuration (`CredProx:Presets`), custom sources |

**Design rules**

1. **`CredProx.Abstractions` package.** Plugin authors depend on a small contract, not core
   internals. `PackageValidation` guards it from accidental breaking changes.
2. **Dogfooding.** Every built-in is implemented through the public plugin API. If a built-in
   needs something private, the contract is incomplete.
3. **Explicit stages.** Request processing runs in fixed stages: *authenticate caller → authorize
   operation → resolve destination → shape headers → attach credential → sign → pipeline
   (throttle, resilience, audit) → send*, and the response gets its own stage, *shape response*
   (M20, §8.2), running at the end of the outbound pipeline before anything is copied to the
   caller. Plugins declare their stage; core enforces the order.
   Signing must run after every other change to the request or signatures break.
4. **Secret scoping.** A plugin receives an `ISecretAccessor` limited to the `secret:` references
   in *its own* configuration. A buggy or malicious plugin cannot read other integrations' secrets.
5. **Typed, validated options.** Each plugin declares an options class; core binds it from
   `CredProx:Credentials:<name>` (or the matching section) and runs `IValidateOptions` at startup.
6. **Explicit registration only.** No assembly scanning. What runs is exactly what the host registered.
7. **Experimental until 1.0.** Plugin interfaces carry `[Experimental("CREDPROX001")]` so authors
   can build on them while the contract can still change. The marker is removed at 1.0.

**Testing kit (`CredProx.Testing`).** A fake token server, fake upstream, captured log sink, and
conformance base classes such as `CredentialProviderConformanceTests<TProvider, TOptions>`. A
plugin author who inherits the base class automatically gets the token-cache, failure-mode,
refresh-on-401 and no-secret-in-logs checks from §5.2. Built-ins run the same conformance suites.

**Vendor presets.** Presets are data, so community contributions need no code review of
executable logic. A preset is validated like any other options object and can be overridden
field by field. Since 0.4.0 the library ships **no built-in vendor presets**: every vendor's
full setup lives in its own sample (§6), and a preset is a distribution choice on top of that —
`CredProx:Presets:<name>` in the host's config or a custom `IPresetSource`. A config that names
one of the removed built-ins fails at startup with an error pointing at the matching sample.

### 3.6 Delegated credentials: token exchange (M14 design)

**Status: APPROVED by the person 2026-10-17** — all four open decisions as recommended;
one correction applied (Rfc8693 sends `subject_token`/`subject_token_type`, not `assertion`).
Implementation is M14 (queue row `qitem-20261017220121-101ce895930d66fd`), gated behind M14a
(the caller allow-list fail-closed fix). §8.1 has listed this feature since the first-release
analysis; this section is its design.

**Purpose.** Every credential so far is a *machine* credential: it authenticates CredProx
itself. A delegated credential authenticates the **user behind the request**: the caller
presents the user's token, CredProx exchanges it at the identity provider (IdP) for a
downstream token scoped to that user, caches it per user, and attaches it. The apps still
never hold vendor secrets — and now they never hold the user's downstream token either.

**One type, two shapes.** A `TokenExchange` credential type with a `Mode` property, following
the `JwtAssertion` precedent (one type, wire-shape enum):

- `Rfc8693` (default) — generic RFC 8693 token exchange:
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, the inbound token sent as
  `subject_token` with `subject_token_type` (default
  `urn:ietf:params:oauth:token-type:access_token`), optional `scope`, `audience`
  (the RFC 8693 §2.1 parameter name — corrected during E14 against real Keycloak; the
  design draft had `aud`), `requested_token_type`, `issued_token_type`, `act`. Keycloak
  and most standards-following IdPs speak this.
- `EntraObo` — Microsoft's on-behalf-of profile:
  `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, the inbound token sent as
  `assertion` plus `requested_token_use=on_behalf_of`. (OBO is a draft-era profile of
  RFC 8693: different grant URN, the RFC 7523-style `assertion` parameter name instead of
  `subject_token`, and one extra parameter; otherwise the same shape.)

Both POST a form to `TokenEndpoint` with client authentication as a Basic header or
`client_secret_post` — the same client-auth choice as `OAuthClientCredentials` — and parse the
response with the same configurable field names (`access_token` / `expires_in` defaults). The
mode only sets wire defaults; every parameter stays overridable in config, so a vendor that
deviates from both shapes remains a config change, not a code change. `TokenEndpoint`,
`Authority` and friends accept the §3.2 template forms (`{partition}` allowed — one credential
can serve per-environment IdPs).

**Inbound token validation — CredProx validates, and audience is mandatory.** The provider
must derive a **non-forgeable user subject** (it keys the cache, below). Taking `sub` from an
unvalidated token lets anyone forge `sub=victim` and poison the victim's cache entry
(negative-cache DoS: the victim's later requests get a cached failure without an IdP call).
So validation — signature, issuer, audience, lifetime — runs **before** the subject is
trusted. Audience is required config, not optional: without it any token the same issuer
minted for any other client becomes exchangeable (token confusion).

- Config: `Authority` (OIDC discovery) **or** explicit `Issuer` + `JwksUri`; `Audience`
  required; `SubjectClaim` default `sub`; `ClockSkew` default five minutes (the JwtBearer
  convention). JWKS is fetched lazily and cached, refreshed on unknown `kid` (the shape
  JwtBearer's configuration manager uses).
- Missing inbound `Authorization` → `401 credprox.inbound_token_missing`; failed validation →
  `401 credprox.inbound_token_invalid` naming only the failure kind (expired / signature /
  audience / issuer) — never the token value. Neither is forwarded; neither reaches the IdP.
- **Dependency decision (the person):** validating RS256/ES256 in core means
  `Microsoft.IdentityModel.Protocols.OpenIdConnect` — the first non-`Microsoft.Extensions.*`
  core dependency beyond YARP (§7), and a deliberate reversal of the `JwtAssertionProvider`
  stance "deliberately not a general JWT library": *signing* a fixed claim set is small,
  *validating* against rotating JWKS is the crypto surface the plan avoids rolling.
  Alternatives considered and rejected: trusting the host's authenticated `ClaimsPrincipal`
  (zero dependency, but the security property then rests on the host's JwtBearer being
  configured with audience validation — which CredProx cannot verify; §9 requires the safe
  path to be the default), and hand-rolled JWKS validation (rejected: exactly the audited-
  crypto category). `HostPrincipal` trust stays a §8 candidate if a real host asks.

**Cache key and lifetime.** The exchanged token is cached per **user**: the provider passes a
combined partition component to the existing `ITokenCache` — `p:<partition>|u:<subject>` (the
`p:` part omitted for unpartitioned credentials) — so the key is
`(credential, partition + subject)` and single-flight, early refresh and negative caching all
apply per user with **no cache-backend contract change**. The raw inbound token is never a key
component (it changes on every refresh — the cache would thrash). The subject is an identifier
like the caller id, not a secret: the combined key may appear in diagnostics; token values may
not. Lifetime: the exchanged token is cached until its own `expires_in − skew` (existing
`TokenCacheOptions`); exchange failures cache only for the negative TTL. A cached downstream
token can outlive the caller's inbound token — the standard OBO trade-off; the window is the
IdP's downstream-token lifetime, documented rather than configurable.

**How the provider receives the inbound token (the contract crux).**
`ICredentialProvider.GetCredentialAsync` gets a `CredentialRequestContext` — today only
`CredentialName` + `Partition`, no request access; its own remarks anticipate this extension
("Init-only properties so later milestones can add context"). M14 adds two members:

- `InboundToken` (init, nullable) — the bearer token from the inbound `Authorization` header,
  populated by `CredentialAttachFeature` **only** for credentials whose options declare a
  marker interface (`IRequiresInboundToken`, alongside `IHasAttachment`). This extends the
  §3.5 rule-4 secret-scoping principle to request-borne secrets: providers that do not
  declare the need never see it. Documented as a secret: never logged, never expanded into
  `{partition}` templates, never a cache key component.
- `CachePartition` (get/set, nullable) — the provider records the effective cache partition it
  used; the attach feature's refresh-on-401 invalidate currently targets
  `(credential, partition)` and will target `CachePartition ?? Partition`, so a 401 from the
  downstream drops the right **per-user** entry. Default `null` keeps today's behaviour for
  every existing provider.

No new plugin interface, no `HttpContext` handed to providers, no breaking signature change.

**Failure semantics.** Added to the §3.4 table above: missing/invalid inbound token → 401
(the *caller's* token is the problem — distinct from §3.4's 502, which is the *proxy* failing
upstream). Exchange endpoint failures — unreachable, 5xx, `invalid_grant` — stay
`502 credprox.credential_unavailable` per §3.4 with negative caching only. A downstream 401 on
a cached exchanged token runs the existing refresh-on-401: invalidate the per-user key,
re-exchange with the same request's inbound token, retry once.

**Interaction with caller keys and allow-lists: orthogonal, no change.** Caller authentication
(Stage `AuthenticateCaller`) answers *which app* — keys, operation allow-lists, throttling,
audit. The exchange (Stage `AttachCredential`) answers *which user*. A caller key is still
required on routes that require one, and the allow-list gates the route before any IdP call
happens. Audit gains the user subject (an identifier, like caller id — never the token). E14
demonstrates both identities on one request.

**Header hygiene.** The exchange credential attaches to `Authorization` (like `JwtAssertion`),
and the attacher's replace-not-merge rule already guarantees the inbound user token never
reaches the downstream. If a future vendor needs the exchanged token in some other header,
hygiene must strip the inbound `Authorization` first — noted, not built (YAGNI).

**Required tests (§5.2 style — becomes a "Token exchange" row at implementation).**

| Area | Cases |
|---|---|
| Wire shape | exact form fields asserted per mode: `Rfc8693` = token-exchange URN + `subject_token` + `subject_token_type` + client auth; `EntraObo` = jwt-bearer URN + `assertion` + `requested_token_use=on_behalf_of` + client auth; parameter and field-name overrides work |
| Inbound validation | bad signature, expired, wrong audience, wrong issuer, `alg=none` → 401 each, **no IdP call, no cache entry**; valid token → exchange proceeds |
| Cross-user isolation | two users concurrently → separate cache entries, each served only its own token (property test, interleaved); a forged `sub` cannot poison another user's key (validation fails before keying) |
| Single-flight | 100 concurrent same-user requests → one exchange call; different users' exchanges do not block each other |
| Failure paths | missing inbound → `401 inbound_token_missing`; exchange 5xx / unreachable / `invalid_grant` → 502, cached only for the negative TTL; refresh-on-401 invalidates the per-user key and re-exchanges once |
| Hygiene and leak | inbound token and exchanged token never appear in logs or audit (scan every captured line); the downstream sees only the exchanged token (validating stub asserts the audience) |
| Config validation | missing `Audience`, missing `Authority`/`Issuer`+`JwksUri`, unknown `Mode` → one clear startup error each |
| Conformance | the built-in passes `CredentialProviderConformanceTests` like every other type |

**Example E14 `samples/TokenExchange`** (offline, Docker — the E2/E7 precedent): a Keycloak
realm with a frontend client (a test user obtains an inbound token via direct grant) and a
downstream client; CredProx runs `TokenExchange` in `Rfc8693` mode to exchange the user token
for a downstream-audience token; a protected downstream API validates its own audience and
echoes the subject. Smoke: user A and user B each receive **their own** downstream token
(proves the per-user cache end to end); a forged inbound token → 401 with no IdP hit; the
caller API key is still required and the allow-list still gates the route; the downstream never
sees the inbound token. Ports: proxy 5092, Keycloak 5094 (5093 is E7's). README ends with the
usual one-request trace.

**Adversarial pass (before M14 closes, per the team's security-milestone rule).** Cross-user
cache leakage; token confusion/audience (tokens minted for other clients or audiences rejected
before any exchange); replay (bearer replay is inherent to the model — CredProx neither
worsens nor claims to fix it; DPoP stays the §8.1 answer); header leakage (inbound token never
forwarded, never logged); negative-cache poisoning via forged subject (validation precedes
keying).

**Open decisions for the person.**

1. **Core dependency:** add `Microsoft.IdentityModel.Protocols.OpenIdConnect` (recommended) —
   vs host-principal trust (rejected: safe path not default) — vs hand-rolled JWKS validation
   (rejected: rolled crypto).
2. **Cache key:** combined partition string + `CachePartition` write-back (recommended; no
   cache-backend break) — vs a third key component on `ITokenCache` (cleaner model, breaks
   every cache backend pre-1.0 for one built-in's need).
3. **E14 runtime:** Keycloak token exchange (recommended; honest exchange, E2/E7 precedent) —
   vs an in-process IdP stub signing test keys (no Docker, more stub code to trust).
4. **Validation-failure status:** 401 (recommended — the caller's token is the problem) — vs
   502 per the generic credential row. Exchange-endpoint failures are 502 either way.

### 3.7 Per-caller budgets (M15 design)

Person-approved 2026-10-17 ("add per-app limits after M14"). Today throttling is per-cluster
only (§3.3, `ThrottleOptions.Clusters`): one chatty app can exhaust a shared upstream for
everyone (the E13 AI-gateway case). M15 gives each **caller** its own request budget,
alongside — not replacing — the per-cluster limit.

**Config shape** (on the caller, `CredProx:Callers:<id>`; opt-in like the allow-list — absent
means unlimited):

```json
"Limits": {
  "PermitsPerInterval": 100,
  "Interval": "00:01:00",
  "Clusters": {
    "openai": { "PermitsPerInterval": 10, "Interval": "00:00:10" }
  }
}
```

A `Clusters:<id>` entry **replaces** the caller default for that cluster (override, not
additive). `PermitsPerInterval: 0` disables. Validation at startup and reload: positive
`Interval` when permits are set; and the new keys go through the M14a unknown-key rejection —
`Limits` joins `CallerLevelKeys` in `CallerBinder` with its own allow-lists for the entry and
`Clusters` levels, so a typo in a budget fails closed, never silently unlimited.

**Where it runs:** a new request feature `CallerBudgetFeature` at a new stage
`Stage.ApplyCallerBudget = 25` — after `AuthorizeOperation` (a blocked operation never
consumes budget) and after `ResolveDestination` (the per-cluster override keys on the
resolved cluster), before `ShapeHeaders`/`AttachCredential` (a rejected request never touches
a token endpoint or the upstream, §3.4). The `Stage` addition is additive to Abstractions
(pre-1.0; contract tests updated). Implementation checkpoint: the resolved cluster id must be
on the request state after `ResolveDestination`; if it is not yet published there, the feature
reads the YARP destination feature.

**How the two limits combine:** two independent gates in order — caller budget (inbound, per
caller × cluster) answers first with `429 credprox.caller_throttled`; the cluster throttle
(outbound, per cluster, with its queue and vendor-pause logic) still answers second with
`429 credprox.throttled`. A request can pass its budget and still be cluster-throttled; that
is the point — the budget protects other callers from this one, the cluster limit protects
the vendor from all of them. Distinct problem codes so callers can tell which limit they hit.

**Mechanics:** fixed-window counting (the `FixedWindowRateLimiter` shape already used by
throttling), one counter per budget key, created lazily. Budget keys come from **config**
(caller id × cluster), never from request data — no attacker- or IdP-controlled key growth.
No queueing at the budget layer: a rejected request gets `429` + `Retry-After` (seconds to
window reset) immediately; queue-and-wait stays the cluster limiter's job.

**Partitioning:** the budget is per **caller id** (the app identity behind the API key) — not
per key id (key rotation must not reset a budget) and not per end user. After M14: a
`TokenExchange` caller's per-user tokens all draw on the one caller budget; per-user or
per-agent cost budgets stay the §8.3 future item (cost caps are a different mechanism).

**Scope, stated plainly:** single-instance, in-memory, per process. Windows reset on restart
and when a reload changes that caller's limits (the changed pair's window is replaced fresh;
a reload that leaves the limits alone does not hand out a fresh budget — simple and honest).
Multi-instance shared budgets need a shared counter (distributed store) — out of scope, and
the docs will say so where the config is documented.

**Audit and metrics:** rejections increment a `credprox.caller_throttle.rejections` meter
instrument tagged `credprox.caller` + `credprox.cluster`; the abort flows through the existing
audit path like other aborts (caller, route, status, problem code — no key material).

**Tests (§5.2 additions):** budget exceeded → 429 + `Retry-After` + `credprox.caller_throttled`;
per-cluster override replaces the default; allow-list-blocked request consumes no budget;
rejected request makes zero token/upstream calls; key rotation does not reset the window;
reload re-binds limits; unknown key under `Limits` fails startup AND reload (M14a); meter
increments. E13 `samples/AiGateway` gains a per-app limit block and loses its "not available
yet" note.

**Open decisions for the person.**

1. **Window type:** fixed window (recommended — matches the existing limiter, `Retry-After`
   is exact to the window reset) — vs sliding window (smoother, ~2× memory, no exact reset
   instant to advertise).
2. **Stage placement:** new `ApplyCallerBudget = 25` stage (recommended — explicit order,
   per-cluster overrides see the resolved cluster) — vs piggybacking `AuthorizeOperation`
   with registration-order coupling (no Abstractions change, implicit order).

---

## 4. Scope of the first release (0.3)

### In

**Phase A — credential core** (formerly 0.1)

| Area | Deliverable | Acceptance |
|---|---|---|
| Core | Feature/hook model, stages, config binding, validation, `CredProx` diagnostics | Unknown reference fails startup with a clear message |
| Credentials | `OAuthClientCredentials` (body or Basic client auth, scopes, audience) | Token fetched once under 100 concurrent requests; refreshed before expiry |
| | `LoginExchange` (any method, Basic or form body, token from JSON path / raw body / header / cookie) | Login-exchange example works from config alone |
| | `StaticKey` (header or query) | — |
| | `TokenCredential` (Azure `TokenCredential` + scope, in `CredProx.AzureKeyVault`) | Managed identity to Graph works |
| | Refresh-on-401 (retry once) | Covered by test with an upstream that rejects the first token |
| Destinations | Partitioned templates with allow-list | Non-allow-listed value → 400, never forwarded, never reaches token endpoint |
| Connections | Client certificate per cluster from a secret, PFX/PEM, reload on rotation | Rotating the secret changes the cert presented on new connections |
| Secrets | `ISecretSource` + configuration source; Azure Key Vault source in add-on | — |
| Hygiene | Inbound key header and partition header always stripped | Asserted by test |
| Plugins | `CredProx.Abstractions`, stage model, secret scoping, explicit registration | All built-ins implemented through the public API |

**Phase B — least privilege and operations** (formerly 0.2)

| Area | Deliverable | Acceptance |
|---|---|---|
| Caller auth | API-key authentication scheme: hashed keys, key ids, expiry, multiple active keys per caller for rotation; plugs into YARP's per-route `AuthorizationPolicy` | Unknown, expired or revoked key → 401; key value never logged |
| Per-caller credentials | Partition source `caller:` so each caller maps to its own vendor account | Caller A and caller B receive different upstream credentials on the same route |
| Operation allow-lists | Per caller: methods + path patterns per route (e.g. read-only analytics callers) | Disallowed operation → 403 and nothing reaches the token endpoint or upstream |
| Caller budgets (M15, §3.7) | Per-caller request budget: permits per interval, optional per-cluster override (null fields inherit); `429 credprox.caller_throttled` + `Retry-After`; unknown keys under `Limits` fail closed (M14a rule) | Budget exceeded → 429 with `Retry-After`, nothing reaches the token endpoint or upstream; one exhausted caller never touches another's budget; LoadTests: a concurrent burst admits exactly the budget and refills only on the window boundary |
| Credential health | Background probes: token obtainable, certificate expiry within N days. Exposed as ASP.NET Core health checks + metrics + warnings | Expiring cert turns health `Degraded` before expiry; failed token probe turns it `Unhealthy` |
| Audit log | One record per proxied call: caller, route, vendor, method, path template, status, latency, bytes, credential name (never value). Header and JSON-field redaction rules. `IAuditSink` | Redacted fields never appear in the sink; audit failure never fails the request |

**Phase C — traffic shaping, breadth, ecosystem** (formerly 0.3)

| Area | Deliverable | Acceptance |
|---|---|---|
| Outbound throttling **(in 0.3)** | Per-cluster rate and concurrency limits (`System.Threading.RateLimiting`), honouring vendor `429` / `Retry-After` by pausing the cluster; bounded queue | Under load the upstream never sees more than the configured rate; vendor 429 pauses traffic for `Retry-After` |
| Resilience | Adapter over `Microsoft.Extensions.Http.Resilience`: retry (idempotent only), attempt timeout, circuit breaker per cluster | POST is never retried unless explicitly enabled; open circuit → 503 |
| JWT assertion | `JwtAssertion` credential: sign an assertion with a key/cert (RS256/ES256/PS256), use as `client_assertion` (`private_key_jwt`) or exchange it (GitHub App, Salesforce JWT bearer, Google service account style) | GitHub App example obtains an installation token |
| HMAC signing | `Hmac` credential: configurable canonical string (method, path, query, selected headers, timestamp, body hash), algorithm, encoding, header layout. Opt-in body buffering with size cap | Signature verified by a reference verifier for 3 canonical-string layouts |
| Vendor presets **(in 0.3)** | `IPresetSource` + config-defined presets (`CredProx:Presets`); the six embedded vendor presets shipped in 0.3 were removed in 0.4.0 — vendor setups live in the samples (§6) | User-defined presets compose with host config; field overrides work |
| Testing kit | `CredProx.Testing` with fakes and conformance suites | All built-in credential types pass their conformance suite |

**Cross-cutting**

| Area | Deliverable | Acceptance |
|---|---|---|
| Tests | Unit, integration, security, container end-to-end, conformance | Coverage gates in §5 pass in CI |
| Examples | Thirteen runnable example projects (§6), including real public vendors | Every example runs from its README; offline ones run in CI |

### Out (after the first release, see §8)

AWS SigV4, token exchange / on-behalf-of, refresh-token grant, session-cookie login, DPoP,
NTLM/Kerberos, placeholder substitution, response scrubbing, agent-specific features (consent
signalling, budgets, approval gates), error normalisation, record/replay, admin endpoint, usage
metering, webhook verification, distributed token cache.

### Non-goals (never)

Body rewriting, pagination following, protocol bridging (SOAP↔JSON), being a general API
management product. These change what a proxy is.

---

## 5. Test coverage

Tests are part of the release deliverable, not a follow-up. A credential broker that silently attaches
the wrong credential, or forwards to the wrong host, is worse than no library.

### 5.1 Test layers

| Layer | Project | What it exercises | Tooling | Runs |
|---|---|---|---|---|
| Unit | `tests/CredProx.Tests` | Token cache, secret resolution, template expansion, config binding and validation, each credential provider against a fake `HttpMessageHandler` | xUnit, `FakeTimeProvider` (`Microsoft.Extensions.TimeProvider.Testing`) for expiry without sleeps | Every PR |
| Integration | `tests/CredProx.IntegrationTests` | Real YARP pipeline in-process: request in → transforms → outbound request as seen by a fake upstream and fake token server | `WebApplicationFactory`/`TestServer`, WireMock.Net | Every PR |
| Property / security | `tests/CredProx.SecurityTests` | Partition allow-list and header stripping against generated hostile input; no secret ever appears in logs, problem responses or forwarded headers | FsCheck, captured `ILogger` sink | Every PR |
| Container end-to-end | `tests/CredProx.E2ETests` | Real OAuth server (Keycloak), real mTLS endpoint (nginx with `ssl_verify_client`), real cert rotation | Testcontainers for .NET (`Testcontainers.Keycloak`, generic container for nginx) | Every PR on Linux; skipped on Windows runners |
| Conformance | `tests/CredProx.ConformanceTests` | Every built-in credential type, secret source and token cache run through the `CredProx.Testing` conformance suites (the same suites plugin authors use) | `CredProx.Testing` | Every PR |
| Load | `tests/CredProx.LoadTests` | Throttling holds the configured rate under burst; circuit breaker opens/closes; token cache stays single-flight under sustained load | NBomber or k6 against the in-process host | Nightly |
| Live vendor smoke | `samples/*` with `--smoke` | The public-vendor examples in §6 against the real services | Manual or nightly workflow with repo secrets | Nightly / pre-release |
| Benchmarks | `tests/CredProx.Benchmarks` | Added latency per request vs plain YARP; token-cache hit path allocations | BenchmarkDotNet | Pre-release, results committed |

### 5.2 Required test cases

Each row is a named test (or test class) that must exist before the phase that introduces the
feature is previewed. All rows must exist before the public release.

| Area | Cases |
|---|---|
| Token cache | single fetch under 100 concurrent requests; refresh before expiry (at 80% / `expires_in − skew`); failure is cached only for the negative TTL, then retried; one key's failure does not affect other keys; `Invalidate` forces a refetch; cancellation of one waiter does not cancel the shared fetch |
| OAuth client credentials | client auth as Basic header and as form body; scope and audience sent; `expires_in` missing → configured default lifetime; non-2xx and malformed JSON → `credential_unavailable` (502) with no forward |
| Login exchange | GET and POST; Basic and form credentials; token from raw body, JSON path, response header, and cookie; per-partition secrets resolved correctly; placement `Header` (default) or `Cookie` — cookie placement replaces the whole caller `Cookie` header (never merges), rejects `;`/CR/LF/NUL values and `Query`/`AttachPrefix` combos, and keeps the value in the cache/refresh/scrub machinery like any other (M23) |
| Token exchange | exact form fields per mode (`Rfc8693`: token-exchange URN + `subject_token` + `subject_token_type`; `EntraObo`: jwt-bearer URN + `assertion` + `requested_token_use=on_behalf_of`); bad-signature/expired/wrong-audience/wrong-issuer inbound → 401 with **no IdP call and no cache entry**; per-user cache isolation (A's token never served to B; a forged subject cannot poison another user's key); exchange-endpoint failure → 502; no token value in any message or log |
| Static key | header and query placement; existing caller value is overwritten, not duplicated |
| Azure `TokenCredential` | scope passed; token cached until `ExpiresOn − skew`; credential exception → 502 |
| Refresh-on-401 | upstream rejects first token → one refetch + one retry → success; second 401 is returned to caller (no loop); non-idempotent request with unbuffered body is **not** retried |
| Destinations | allowed value expands correctly; disallowed value → 400 and **no call reaches the token endpoint or the upstream**; hostile values (`attacker.com/app?`, `app#`, `app@evil`, `../`, `%2e`, unicode homoglyphs, CRLF, empty, very long) all rejected (property test) |
| Connections | PFX and PEM certs; wrong password → startup validation error; secret rotation → next connection presents new cert (verified by the mTLS container echoing the client cert subject) |
| Header hygiene | inbound key header and partition header never reach the upstream; caller-supplied `Authorization` is replaced, not merged |
| Secrets | `secret:` references resolve; missing secret → validation error naming the reference (not the value); config reload updates resolved values |
| Validation | unknown `CredProx.Credential` / `CredProx.Connection` reference; unknown credential `Type`; destination without allow-list; each produces one clear `OptionsValidationException` at startup |
| Diagnostics | metrics emitted for fetch success/failure, cache hit/miss; secret values never appear in logs at any level (asserted by scanning captured log output for every configured secret) |
| Plugin model | stages run in declared order regardless of registration order; signing stage sees the final request; a plugin's `ISecretAccessor` cannot resolve secrets outside its own config; unregistered plugin type in config → startup error; built-ins resolve only through public API (architecture test with NetArchTest) |
| Caller API keys | valid key → caller identity; unknown, expired, revoked key → 401; two active keys for one caller both work during rotation; keys compared in constant time; key value absent from logs and audit |
| Per-caller credentials | callers A and B on the same route get different upstream credentials and separate token-cache entries; caller with no mapping → 403, no token fetch |
| Operation allow-lists | allowed method+path → forwarded; disallowed method, disallowed path, path-traversal variants (`/a/../admin`, encoded slashes, case tricks) → 403 and nothing reaches token endpoint or upstream (property test) |
| Caller budgets (M15, §3.7) | budget exceeded → 429 `credprox.caller_throttled` with `Retry-After`, nothing reaches token endpoint or upstream; window reset re-admits; per-cluster override replaces the default field-by-field (unset fields inherit, `0` disables for that cluster); key rotation shares the budget; one exhausted caller never touches another's budget; unknown keys under `Limits` fail closed at startup **and** reload (M14a rule); LoadTests: a concurrent burst admits exactly the budget and refills only on the window boundary; a concurrent rebind never disposes a live limiter and the settled budget stays exact |
| Credentials unknown keys (M16, §3.3) | unknown key under a credential section — top level, nested block, preset-supplied, or a plugin type's section — fails startup **and** reload (previous registry keeps serving) naming the credential and key; a misspelled optional field (`Scopee` for `Scope`) is rejected with the real key in the known-keys list; get-only computed keys rejected; a nested block under a scalar or the `Type`/`Preset` keys (`Scope:From`, `Preset:Name`) rejected; a valid rich config (scalars, enums, nested `Partition`, leaf-array indices, any casing) binds |
| Kill switch (M18, §8.4) | `CredProx:KillSwitch` cluster/caller id lists take a vendor or caller out of service live: disabled cluster → `503 credprox.vendor_disabled`, disabled caller (after its key validated — never an anonymous bypass) → `503 credprox.caller_disabled`, neither forwarded nor reaching a token endpoint; flip off/back across reloads; a failed rebind keeps the previous switch state; the section is fail-closed (unknown key, single value instead of a list, non-index entry, blank id all refuse startup **and** reload); empty switch serves everything |
| Sections unknown keys (M17, §3.3) | unknown key under `CredProx:Destinations`/`CredProx:Connections` fails startup **and** reload (previous registry keeps serving) naming the entity and key; a nested block under a single-value key (`Partition:From`, `ClientCertificate:Blob`) rejected; a per-cluster field typo (`Clusters:vendor:PermitsPerIntervall`) rejected while cluster names stay free; unknown keys under `CredProx:Audit`/`Health`/`Throttling`/`Resilience` fail startup eagerly; at the `CredProx` root an unknown key or a misspelled section name (`Throteling`) fails startup; the full known topology and every valid rich section config (typed cluster dictionaries, list indices, any casing) bind |
| Consent signalling (M19, §8.3) | provider throws `ConsentRequiredException` → `401 credprox.consent_required` with the `authorize_url` extension member verbatim, **no forward and no token-endpoint call**; URL hygiene — absolute http(s) URLs are surfaced, relative references / non-browser schemes (`javascript:`, `ftp:`, `file:`) / embedded credentials / whitespace are dropped from the body while the consent problem still lands; consent stays distinct from `inbound_token_*` on delegated routes; refresh-on-401 — consent on the refresh fetch returns the upstream's own 401 (never 500, no retry attempted, the rejected token still invalidated); standalone handler composition propagates the typed exception to its caller |
| Response scrubbing (M20, §8.2) | an injected value reflected into the body/header/gzipped body is replaced with `[redacted]` before the caller sees it (integration: header-placement echo body, response headers, gzipped body, and the query-placement URL echo on the live Kestrel host); the streaming matcher finds a secret split at **any** read boundary, including mid-UTF-8 sequence, adjacent matches, and overlapping patterns longest-first; the encoded form of a query-placement secret is scrubbed too; the refresh-on-401 replacement token is registered alongside the first; gate chain: disabled flag, no registry, empty registry, missing/binary content-type, and empty body all pass through **byte-identical**; gzip/deflate/br of eligible types decode-scrub-forward with `Content-Encoding` dropped, undecodable (zstd) or chained encodings warn and pass through; non-UTF-8-charset bodies are a documented blind spot — patterns try raw/UTF-8/encoded forms, so UTF-16's interleaved bytes never match, and those bodies flow byte-identical; scrubbed framing never carries a stale `Content-Length`; multi-value headers keep their other values; `text/event-stream` scrubs **per event** (M22): events flush as they complete — streaming latency survives — with within-event matching exact (a secret split across an event boundary is the framing's documented residue) and an unterminated event above the buffer cap degrading safely to byte-stream hold-back semantics; plugin `IResponseFeature` dispatched on the real pipeline after the built-in; security property: the generated secret value never appears in the caller-facing bytes whatever its content, across body/gzip/event/header |
| Vendor error normalisation (M24, §8.5) | a vendor `4xx`/`5xx` text-like body becomes `application/problem+json` with the status preserved and the vendor payload embedded losslessly (`vendor_detail` parsed when it parses — objects and arrays, malformed JSON degrades to raw text, empty body omits the member; `vendor_content_type` beside it; `extensions.code: credprox.vendor_error`); the rewriter sees only already-scrubbed bytes (integration: a reflecting vendor 400/500 arrives as a problem document carrying `Bearer [redacted]`, never the token — the scrubber→normaliser order is asserted on the DI-resolved pipeline via the stable same-stage registration order); gate chain byte-identical: `<400`, `HEAD`, `text/event-stream`, binary/unknown/missing content type, declared charsets outside UTF-8/US-ASCII (review F1: a Latin-1 or UTF-16 body would arrive corrupted in the text embed — live and feature tests replay its exact bytes, with the charset warned; absent/`utf-8`/`us-ascii` normalise), undecodable and chained encodings; gzip errors normalise from the decoded bytes; the cap bounds both the buffered compressed bytes and the decoded form (gzip bomb: the caller receives the exact compressed payload, warning logged); over-cap flows byte-identical, never truncated — including a partially-read undeclared body (prefix + remainder replay survives the copy loop's zero-length probe); a body exactly at the cap still normalises; opt-outs: global `Enabled=false`, route metadata `"off"` case-insensitive (unknown values normalise), contexts without the YARP feature keep the default-on posture; the replacement carries the document's exact `Content-Length` and vendor response-level headers (`Retry-After`) survive untouched, while the dropped vendor content headers include `Content-Range` on a `416` — range-sensitive APIs opt their route out; proxy-produced problems carry `urn:credprox:errors:proxy`, rewrites `urn:credprox:errors:vendor`; `CredProx:Errors` unknown keys and a non-positive cap refuse startup; security property: the generated secret never reaches the caller's bytes through the embed (JSON and text), and the over-cap replay is byte-exact for arbitrary generated bodies |
| Credential health | expiring cert → `Degraded` N days before; failed token probe → `Unhealthy`, recovers on success; probes respect the token cache (no extra token calls when a valid token is cached) |
| Audit | one record per call with the documented fields; redacted headers/JSON fields never reach the sink; sink exception does not fail or delay the proxied request beyond a bound; records carry the trace id |
| Throttling | upstream never exceeds configured rate/concurrency under burst; queue limit → 429 with `Retry-After`; vendor 429 + `Retry-After` pauses the cluster for that duration; limits are per cluster, not global |
| Resilience | GET retried on transient failure; POST not retried unless enabled; attempt timeout enforced; circuit opens after threshold → 503, half-opens and closes |
| JWT assertion | RS256 / ES256 / PS256 signatures verify against the public key; `iss`/`sub`/`aud`/`exp`/`iat`/`jti` set correctly; unique `jti` per assertion; clock skew applied; GitHub App flow obtains installation token against a stub |
| HMAC signing | three canonical-string layouts verified by an independent reference verifier; body hash correct for empty, small and max-size bodies; body over the cap → 413; signing runs after header shaping; timestamp uses `TimeProvider` |
| Presets | user-defined preset (config or custom `IPresetSource`) validates and binds; field-level override works; unknown preset → startup error; a removed built-in name → startup error naming it and pointing at its sample; preset cannot introduce a secret reference the host did not configure |
| Compatibility | full integration suite runs on `net10.0` (the only target since the M5 gate, 2026-10-14) |

### 5.3 Coverage gates

| Metric | Gate | Tool |
|---|---|---|
| Line coverage, `CredProx` core | ≥ 90% | coverlet (`XPlat Code Coverage`) + ReportGenerator |
| Branch coverage, `CredProx` core | ≥ 80% | same |
| Line coverage, add-on packages | ≥ 80% | same |
| Line coverage, `CredProx.Abstractions` + `CredProx.Testing` | ≥ 80% | same |
| Mutation score, token cache, destinations, allow-lists, signing | ≥ 70% (reported, not blocking for the first release) | Stryker.NET, nightly |

Coverage reports are attached to every PR (CI job summary / artifact). A PR that lowers core
coverage below the gate fails. Coverage is a floor, not the goal: §5.2 is the real definition of
"tested".

---

## 6. Example projects

Examples are the main documentation. Each one is a small, runnable ASP.NET Core host with its own
README that states: what it demonstrates, what you need (nothing / Docker / a free vendor account),
the exact config, and a `curl` command showing the request **without** a credential going in and
the upstream receiving one.

All examples use **configuration only** for the vendor integration, with no vendor-specific C#.
That is the point they demonstrate.

| # | Project | Demonstrates | Needs | Runs in CI |
|---|---|---|---|---|
| E1 | `samples/QuickStart` | Smallest possible host. `StaticKey` injected into calls to a public echo service (`postman-echo.com/headers`); the response shows the header the upstream received | Nothing | Yes (as a smoke test against a WireMock stand-in; live call optional) |
| E2 | `samples/OAuthKeycloak` | `OAuthClientCredentials` end to end: Keycloak issues tokens, a small protected API validates them, CredProx sits in between. Shows single-flight, refresh, and refresh-on-401 (via a Keycloak token revocation script) | Docker (`docker compose up`) | Yes |
| E3 | `samples/MutualTls` | Client certificate per cluster. Two variants: a local nginx that requires a client cert and echoes its subject (runs offline), and the public `client.badssl.com` test endpoint with BadSSL's published test certificate. Includes a cert-rotation walkthrough | Docker for local; nothing for badssl | Local variant: yes |
| E4 | `samples/Spotify` | A real public vendor in explicit config: OAuth client credentials (`accounts.spotify.com/api/token`, Basic client auth). Calls the Web API catalogue endpoints through CredProx | Free Spotify developer app | Nightly smoke |
| E5 | `samples/MicrosoftGraph` | Two credential styles against Graph, both explicit config: Entra app client credentials (`https://graph.microsoft.com/.default`), and Azure `TokenCredential` / managed identity with **no stored secret**. Shows Key Vault as the secret source | Entra tenant + app registration; Azure for the managed-identity variant | Nightly smoke (client-credentials variant) |
| E6 | `samples/ADP` | ADP's shape as config: OAuth client credentials **plus** mTLS on both the token call and the API calls. Ships WireMock mappings that mimic the vendor so it runs without accounts; switch to the real endpoints via config | Nothing (WireMock); real vendor accounts optional | Yes (WireMock mode) |
| E7 | `samples/PerCallerCredentials` | Inbound API keys; two callers mapped to different vendor accounts on the same route; a read-only caller blocked from POST by its allow-list; audit records for all three | Docker (Keycloak as the vendor) | Yes |
| E8 | `samples/GitHubApp` | `JwtAssertion` → GitHub App installation token → GitHub REST API, the whole flow in explicit config: the generic JwtAssertion in `BearerExchange` mode with GitHub's response shape | A GitHub App (free) | Nightly smoke; stub mode in CI |
| E9 | `samples/HmacSigning` | `Hmac` credential against a local signature-verifying stub API; shows canonical-string configuration and body buffering limits | Nothing | Yes |
| E10 | `samples/CustomPlugin` | Writing a plugin: a custom credential type in ~50 lines, registered explicitly, tested with `CredProx.Testing` conformance suites. The template for community plugins | Nothing | Yes |
| E11 | `samples/Operations` | Throttling under load with a vendor stub that returns 429 + `Retry-After`, circuit breaker, health checks and dashboards (Aspire AppHost wiring E2, E3, E6) | Docker | Yes (load script shortened) |
| E12 | `samples/LoginExchange` | Vendor-neutral session login: `LoginExchange` form login against a WireMock stub, `{partition}` per-environment partitions (one credential serves many environments), and the partition allow-list — the mechanism the old HrIntegrations Cayuse demo showed | Nothing (WireMock) | Yes |
| E13 | `samples/AiGateway` | AI provider gateway: internal apps authenticate with their own caller API keys, CredProx injects the real provider key (`StaticKey` header), per-caller operation allow-lists (chat-only vs. admin/files blocked), per-caller request budgets (`Limits`, M15: one chatty app cannot exhaust the shared provider for the others), cluster throttling, audit records — SSE streaming passthrough proven by an in-process stub that flushes two events 400 ms apart | Nothing (in-process provider stub) | Yes |
| E14 | `samples/TokenExchange` | `TokenExchange` (Rfc8693) against real Keycloak 26: CredProx validates the caller's inbound user token (signature/issuer/audience/lifetime), exchanges it per user for a downstream-audience token, and the protected downstream's audience check proves the inbound token never reaches it; forged inbound → 401 with no exchange; caller key still required | Docker (Keycloak 26.2, standard token exchange) | Yes |
| E15 | `samples/AgentEgress` | AI agent egress (§8.3): an MCP-server/agent runtime calls a Salesforce-shaped vendor through CredProx holding **only its own caller key** — per-agent operation allow-lists as tool boundaries (CRM agent reads, support agent opens cases, neither can do the other's job), `OAuthClientCredentials` in `FormPost` client-auth (Salesforce's spelling), one shared credential whose cached session token both agents ride (token-endpoint issuance count proves it), and response scrubbing (§8.2) removing the session token the stub's `debug_authorization` field echoes back; README carries the MCP production topology and the real-org switch | Nothing (in-process Salesforce stub) | Yes |
| E16 | `samples/SessionCookie` | Session-cookie login (§8.1) — the generic successor to the original Cayuse demo (F6's `Mode: Contains` environment header becomes a strict allow-list): `LoginExchange` POSTs a form login, captures the `Set-Cookie` session and replays it (`Location: Cookie`, replaced not merged — caller cookies never reach the vendor), `{partition}` per-environment accounts and secrets with one login each, transparent refresh through a server-side 401, scrubbing of the session the stub's `debug_cookie` field echoes back, and the M24 showcase: a vendor 404 arrives at the caller as a normalised RFC 7807 problem (`urn:credprox:errors:vendor`, scrubbed `vendor_detail`) while the opted-out `/crm-raw/...` route (`"CredProx.ErrorNormalisation": "off"`) returns the vendor body byte-as-written | Nothing (in-process CRM stub) | Yes |

No sample references a built-in preset: since 0.4.0 the library ships none, and every vendor's
full setup is plain config in its own isolated sample.

### Planned after the first release

| Example | Shows |
|---|---|
| `samples/AwsSigV4` | Calling AWS APIs through `CredProx.Aws` |

### Example quality bar

- Each example builds and runs against the **released package**, not a project reference. A CI job
  repoints examples to the freshly packed `.nupkg` before release, which catches packaging mistakes.
- No real secret is ever committed. Examples read secrets from user-secrets or environment variables
  and fail with a clear message naming the missing value.
- Every README ends with a "what just happened" section that traces one request through CredProx.

---

## 7. Engineering and release

- **Targets:** `net10.0` only (the person dropped .NET 8 at the M5 gate, 2026-10-14; was `net8.0;net10.0`). Core is a class library (`Microsoft.NET.Sdk`), not a web project.
- **Dependencies (core):** `Yarp.ReverseProxy` 2.3.x, `Microsoft.Extensions.*` abstractions only.
- **Layout:**
  ```
  src/CredProx.Abstractions/          plugin contract
  src/CredProx/                       core + built-in features
  src/CredProx.AzureKeyVault/         add-on: Key Vault secret source, TokenCredential
  src/CredProx.Testing/               fakes + conformance suites for plugin authors
  tests/CredProx.Tests/               unit
  tests/CredProx.IntegrationTests/    in-process YARP + WireMock.Net
  tests/CredProx.SecurityTests/       property tests, secret-leak checks
  tests/CredProx.ConformanceTests/    built-ins through CredProx.Testing
  tests/CredProx.E2ETests/            Testcontainers: Keycloak, nginx mTLS
  tests/CredProx.LoadTests/           throttling, circuit breaker, cache under load
  tests/CredProx.Benchmarks/          BenchmarkDotNet
  samples/                            E1–E16 (§6)
  ```
- **Repository:** `https://github.com/GravLabs/cred-prox` is the canonical source home
  (M25, person-approved 2026-10-29); the internal Gitea repo remains the `origin` remote
  and the package-registry host for the current release line. The POC history is imported
  so the provenance is kept; the POC projects move to `poc/` in M1 and are deleted once
  E6 replaces them.
- **CI:** GitHub Actions (`.github/workflows/`).
  PR workflow: build + unit + integration + security + conformance, E2E (needs Docker on the
  runner), coverage gates, offline examples. Nightly: live vendor smoke tests, load tests, Stryker.
  Linux runner is required; a Windows runner is optional (the code has no Windows-specific paths
  except certificate key-storage flags, which get a unit test on each OS when available).
- **Packages:** previews (`0.3.0-preview.N`, one per phase) publish to the **Gitea NuGet package
  registry** for internal use; releases publish there too (plan §9 decision 3; nuget.org
  postponed — see PUBLISHING.md).
- **Public source:** resolved by M25 — GitHub (`GravLabs/cred-prox`) is the public home for
  SourceLink, issues and contributions; the launch is a squashed clean-start snapshot, no
  full history. See §9 decision 2.
- **Package quality:** SourceLink, deterministic build, symbols package, XML docs, README in package,
  `PackageValidation` baseline set at the public release.
- **Repo hygiene:** `SECURITY.md`, `CONTRIBUTING.md` (including how to contribute presets and
  plugins), changelog, issue templates.
- **Licence:** MIT (unchanged). Because `Forwarder.cs` is removed, no copied .NET Foundation code remains.

### Milestones

| # | Phase | Milestone | Rough effort |
|---|---|---|---|
| M1 | A | Repo restructure, `CredProx.Abstractions` + stage model, core skeleton, Gitea Actions CI with coverage | 1.5 days |
| M2 | A | Token cache + secret source (with scoping) + validation, unit tests | 1.5 days |
| M3 | A | Credential providers (OAuth CC, LoginExchange, StaticKey, TokenCredential) + refresh-on-401, unit + integration tests | 2 days |
| M4 | A | Destinations, connections/cert reload, client factory subclass, security property tests | 1.5 days |
| M5 | A | Container E2E (Keycloak, nginx mTLS); examples E1–E6; **preview 1** to Gitea registry | 2.5 days |
| M6 | B | Caller API-key auth, per-caller credentials, operation allow-lists, with tests | 2.5 days |
| M7 | B | Credential health probes, audit log + redaction + sinks, with tests; example E7; **preview 2** | 2.5 days |
| M8 | C | Outbound throttling + resilience adapter, load tests | 2 days |
| M9 | C | JwtAssertion + Hmac credential types (body buffering), with tests; examples E8, E9 | 2.5 days |
| M10 | C | Presets (mechanism + 6 presets), `CredProx.Testing` + conformance suites; examples E10, E11; **preview 3** | 2.5 days |
| M11 | — | Benchmarks, docs, security self-review, examples against packed `.nupkg`, public release `0.3.0` | 2 days |
| M12 | — | Remove the six built-in presets (breaking, targets `0.4.0`): every vendor an isolated explicit-config sample — E6 split to `samples/ADP`, new E12 `samples/LoginExchange` — removed-preset startup error pointing at the sample | 1 day |
| M13 | — | Example E13 `samples/AiGateway`: AI provider gateway on existing features — caller keys, `StaticKey` provider-key injection, per-caller operation allow-lists, cluster throttling, audit, SSE passthrough | 0.5 days |
| M14a | — | Fix (person-approved 2026-10-17, from the M13 finding): the caller allow-list **fails closed on config typos** — unknown keys under `CredProx:Callers` (incl. nested allow-list entries) and `CredProx:CallerAuth` refuse startup and reload with an error naming the caller and key | 0.5 days |
| M14 | — | `TokenExchange` credential type (design §3.6, signed off 2026-10-17; starts after M14a): RFC 8693 + Entra OBO modes, CredProx validates the inbound user token (signature/issuer/audience/lifetime), per-user cache key `(credential, partition + subject)`, `CredentialRequestContext` gains `InboundToken`/`CachePartition`, example E14 `samples/TokenExchange` (Keycloak), adversarial pass before close | 2.5 days |
| M15 | — | Per-caller request budgets (design §3.7, signed off 2026-10-18): caller `Limits` block (permits per interval, optional per-cluster override), `CallerBudgetFeature` at `Stage.ApplyCallerBudget`, `429 credprox.caller_throttled` + `Retry-After`, M14a unknown-key rejection extended to `Limits`, E13 shows per-app budgets | 1 day |
| M16 | — | Fail-closed unknown-key validation for `CredProx:Credentials` (person-approved, from the §8.6 backlog): keys the credential's options type does not declare — top level, nested blocks, preset-supplied, or a plugin type's section — refuse startup **and** reload (previous registry keeps serving) with an error naming the credential and key; allowed keys derived from the options type by reflection so plugins declare their own keys; `samples/MicrosoftGraph` variants split their credential files (null-clearing across types is now rejected) | 0.5 days |
| M17 | — | Fail-closed unknown-key validation for the remaining sections (person-approved 2026-10-19, from the §8.6 backlog): unknown keys under `CredProx:Destinations`/`CredProx:Connections` refuse startup **and** reload (previous registry keeps serving); `CredProx:Audit`/`Health`/`Throttling`/`Resilience` and unknown keys or misspelled section names under the `CredProx` root refuse startup; typed cluster-dictionary entries validated against their options type; the M16 walker extracted into the shared `ConfigKeyValidator` | 0.5 days |
| M18 | — | Kill switch (person-approved 2026-10-20 as the first of the approved §8 batch, §8.4): `CredProx:KillSwitch` takes clusters and callers out of service by config, live on reload — `Stage.ApplyKillSwitch` answers `503 credprox.vendor_disabled`/`credprox.caller_disabled` before any forwarding or token work, a failed rebind keeps the previous switch state, and the section itself is fail-closed (walker list rule: non-index list entries refuse startup; a blank id or a single value instead of a list too) | 0.5 days |
| M19 | — | Consent-required signalling (person-approved 2026-10-20 as part of the §8 batch; design signed off with the person: plugin contract, 401): Abstractions gains `ConsentRequiredException(authorizeUrl, message)`; the attach feature maps it to `401 credprox.consent_required` with the `authorize_url` problem extension member (surfaced only for an absolute http(s) URL without credentials) and never forwards; refresh-on-401 keeps the upstream's own 401 when the refresh reports consent (no 500, no retry); `samples/CustomPlugin` demonstrates the plugin-side signal; the future refresh-token grant (§8.1) emits the same signal natively | 0.5 days |
| M20 | — | Response secret scrubbing (person-approved 2026-10-20, third of the approved §8 batch after M18/M19, §8.2): any value the pipeline injected is removed if upstream reflects it back — streaming-aware byte matcher (cross-chunk, longest-first, UTF-8 safe), response headers + text-like bodies, gzip/deflate/br decoded-scrubbed-forwarded transparently, encoded form covered; default-on with global `CredProx:Scrubbing:Enabled=false` opt-out; ships as the first built-in `IResponseFeature` at the new `Stage.ShapeResponse`, dispatched end-of-pipeline pre-copy; security milestone: adversarial pass before close | 1 day |
| M21 | — | Example E15 `samples/AgentEgress` (plan §8.3, person-approved 2026-10-20 as the fourth of the approved §8 batch): AI agent egress — an MCP-server/agent runtime holds only its own caller key; per-agent operation allow-lists are the tool boundaries; Salesforce `OAuthClientCredentials` in `FormPost` client-auth as pure config; one shared credential whose cached session token serves both agents (issuance count proves it); the M20/M22 scrubber removes the session token the stub echoes in `debug_authorization`. README carries the MCP production topology and the real-org switch | 0.5 days |
| M22 | — | SSE event-framed scrubbing (person decision 2026-10-20, found by the E13 smoke after M20 closed): `text/event-stream` was byte-scrubbing, and the matcher's hold-back delayed every event by the longest secret's look-ahead — breaking E13's shipped streaming guarantee. Events now flush as each completes, with exact within-event matching; a secret split across an event boundary is the documented residue; unterminated events past the 64 KiB cap degrade to byte-stream hold-back semantics (memory bounded, no leak). E13 expectations updated: the stub's echoed key now arrives `[redacted]` (the stub's own 200-vs-401 check proves injection happened). Matcher core extracted as the shared `SecretScrubber` primitive — one audited implementation behind both framings | 0.5 days |
| M23 | — | Session-cookie login (§8.1, person-selected 2026-10-20 for 0.7: "a generic version of the original cayuse example"): `LoginExchangeOptions` gains `Location` (`Header` default, or `Cookie`) and `Name` (cookie mode defaults the name to `ResponseField`); cookie placement replaces the entire `Cookie` header — never merges, so caller cookies never travel to the vendor — with value guards (`;`/CR/LF/NUL refused) and fail-closed startup rules (cookie must be named, `Query` placement and `AttachPrefix` refused for this type); extraction and placement stay independent (`Location: Cookie` with any `Response` mode); cache, refresh-on-401, scrubbing and audit apply unchanged. Example E16 `samples/SessionCookie`: the generic Cayuse-shaped vendor — form login → `Set-Cookie`, `X-API-Env` strict allow-list closing the F6 host-swap bug class, per-environment accounts and secrets, transparent refresh through server-side expiry, scrubbed `debug_cookie` echo | 1 day |
| M24 | — | Vendor error normalisation (§8.5, person-approved 2026-10-20 as the second of the 0.7 pair, security milestone): a vendor's `4xx`/`5xx` text-like error body becomes a uniform RFC 7807 `application/problem+json` document, default-on — status preserved verbatim, the vendor's payload lossless as the `vendor_detail` extension member (parsed JSON when it parses, raw text otherwise) beside `vendor_content_type` under `extensions.code: credprox.vendor_error`; `type` identifies the origin (`urn:credprox:errors:vendor` for rewrites; proxy-produced problems now carry `urn:credprox:errors:proxy`). Runs strictly on already-scrubbed bytes: registered after the §8.2 scrubber in the same `Stage.ShapeResponse`, an ordering the pipeline's stable sort makes structural, not conventional. Cap `CredProx:Errors:MaxNormalisedBodyBytes` (default 8192, positive enforced) bounds the buffered compressed bytes and the decoded form (a gzip bomb cannot decode past it into the document); over-cap, `HEAD`, `text/event-stream`, non-text/unknown content, declared charsets outside UTF-8/US-ASCII (review F1 — never re-encoded into the embed) and undecodable/chained encodings pass through **byte-identical, never truncated** (buffered prefix + unread remainder — the zero-length probe a copy loop opens with consumes no state). Opt-outs: `CredProx:Errors:Enabled=false` globally, route metadata `"CredProx.ErrorNormalisation": "off"` per route (case-insensitive, near-misses normalise). `CredProx:Errors` joins the fail-closed unknown-key topology. E16 extended: normalised vendor 404 on `/crm/...`, byte-as-written on the opted-out `/crm-raw/...`; ride-alongs: N2 cookie-value hardening (above-ASCII refused — headers travel Latin-1) and the PUBLISHING.md `http-cache --clear` runbook line. Adversarial pass before close | 1 day |
| M25 | — | GitHub public pivot (person-approved 2026-10-29): the source home becomes `https://github.com/GravLabs/cred-prox` — package metadata, SourceLink and every live link repointed; the PackageValidation baseline moves from LAN-feed restore to the published bytes committed under `build/baselines` (ADR-0001), so validation runs identically here and on a GitHub-hosted runner; `.gitea/` becomes `.github/` with real GitHub Actions workflows; the tracked tree is scrubbed of live internal endpoints and machine-local config. The package registry is unchanged (nuget.org still deferred); no public API change, no version bump | 0.5 days |

Total: about **23–25 focused days (roughly five weeks)**. About half of that is tests, examples
and documentation. Each preview is usable on its own, so going straight to the 0.3 scope does not
mean waiting five weeks for anything usable.

---

## 8. Feature analysis beyond the first release

Features marked **(in 0.3)** below are now part of the first release (§4); they stay listed here
for the analysis.

Grouped by theme, with an estimate of value, effort, and which hook each uses. "Value" is relative
to CredProx's positioning, not general usefulness.

### 8.1 More credential types

| Feature | Description | Value | Effort | Hook |
|---|---|---|---|---|
| JWT client assertion (`private_key_jwt`) **(in 0.3)** | Sign an assertion with a key/cert; Salesforce, Google, Entra, many enterprise IdPs | High | S | Request |
| HMAC request signing **(in 0.3)** | Configurable canonical string (method, path, timestamp, body hash), algorithm, header layout. Covers a long tail of SaaS APIs | High | M | Request (needs body buffering) |
| AWS SigV4 | Proxy to AWS services / API Gateway without SDKs in consumers | Medium | M | Request (`CredProx.Aws`) |
| Token exchange (RFC 8693) / Entra on-behalf-of **(M14 — design §3.6)** | Exchange the **caller's** inbound token for a downstream token. Moves CredProx from machine-only to user-delegated | High | M | Request |
| Refresh-token grant with stored refresh token | For vendors that only offer authorization-code flows; CredProx holds and rotates the refresh token | Medium | M | Request + secret write-back |
| Session cookie login **(M23)** | **Done** — `LoginExchange` gained `Location: Cookie` placement: the captured session cookie is replayed as the whole `Cookie` header (replaced, never merged, so caller cookies never ride along), extraction and placement are independent, and the generic Cayuse successor is example E16 `samples/SessionCookie` | Medium | S | Request |
| DPoP (RFC 9449) | Sender-constrained tokens; generate a DPoP proof per request. Forward-looking for FAPI / open banking | Low–Med | M | Request |
| NTLM/Kerberos to on-prem | Proxy modern callers to Windows-auth internal systems | Low–Med | S | Connection (`handler.Credentials`) |
| Duende backend | `ITokenCache` backed by Duende.AccessTokenManagement for teams already licensed | Low | S | Add-on |

### 8.2 Caller identity and least privilege

| Feature | Description | Value | Effort | Hook |
|---|---|---|---|---|
| Inbound API-key auth scheme **(in 0.3)** | ASP.NET Core has none built in. Hashed keys, key ids, expiry, rotation; plugs into YARP's per-route `AuthorizationPolicy` | High | S | ASP.NET auth handler |
| Per-caller credential mapping **(in 0.3)** | Caller A uses vendor account X, caller B uses Y (e.g. per business unit). Partition source `caller:` alongside `header:` | High | S | Request |
| Per-caller operation allow-lists **(in 0.3)** | Method + path patterns per caller (e.g. analytics callers read-only). Finer than route matching | High | M | Request |
| Placeholder substitution | Caller sends `Bearer {{credprox:adp}}` or a placeholder in a header; proxy swaps in the real secret. Lets tools that insist on "having a key" work without one | Medium | S | Request |
| Response secret scrubbing **(M20, M22)** | **Done** — values the pipeline injected (raw and URL-encoded, including the refresh replacement) are removed from what upstream reflects back: response headers and text-like bodies stream through a cross-chunk byte matcher; `text/event-stream` scrubs per event (M22) so streaming latency survives; gzip/deflate/br of eligible types are decoded, scrubbed, forwarded decompressed (`Content-Encoding` dropped); default-on per response, host opt-out `CredProx:Scrubbing:Enabled=false`; binary/unknown bodies, undecodable encodings (zstd), and secrets split across SSE event boundaries are the documented pass-through residues; a body with a non-UTF-8 declared charset is a pre-M24 blind spot (patterns try the raw, UTF-8, and encoded forms — UTF-16's interleaved bytes never match) and such bodies pass through byte-identical; M24's charset gate keeps this scoped rather than widened | Medium | M | Response (`Stage.ShapeResponse`) |

### 8.3 AI agent egress (positioning opportunity)

Agents running MCP tools or HTTP calls are the fastest-growing consumers of third-party APIs, and
"never give the agent the key" is the security principle vendors now push. CredProx already fits:
the agent calls `https://credprox/salesforce/...` with only a CredProx caller key. Additions that
make this explicit:

| Feature | Description | Value | Effort |
|---|---|---|---|
| Agent profile docs + sample **(M21)** | **Done** — example E15 `samples/AgentEgress`: MCP server / agent → CredProx → Salesforce-shaped vendor holding only its per-agent caller key; operation allow-lists are the tool boundaries; the README carries the production MCP topology and the real-org switch | High | S |
| Consent-required signalling | **Done** — M19: a provider that knows the user has not consented throws Abstractions' `ConsentRequiredException(authorizeUrl)`; the core answers `401 credprox.consent_required` with the URL as the `authorize_url` problem member (only when it is an absolute http(s) URL without credentials) and the refresh-on-401 path keeps the upstream's own 401. A future refresh-token grant (§8.1) emits the same signal natively | Medium | M |
| Per-agent budgets | Request caps per caller landed in M15 (§3.7: fixed window, optional per-cluster override, `429 credprox.caller_throttled`); cost caps and day-granularity tuning remain open | Medium | M |
| Human-approval gate | Certain operations (e.g. `POST /payroll/*`) held until approved via webhook | Low (for now) | L |

### 8.4 Traffic shaping and resilience

| Feature | Description | Value | Effort | Hook |
|---|---|---|---|---|
| Outbound throttling | Per-cluster rate/concurrency limiter (`System.Threading.RateLimiting`), honours `Retry-After` and 429, queues briefly instead of failing | High | M | Pipeline |
| Resilience adapter **(in 0.3)** | Retry (idempotent only), timeout, circuit breaker via `Microsoft.Extensions.Http.Resilience` | Medium | S | Pipeline |
| Idempotency keys | Inject `Idempotency-Key` on POST so retries are safe where vendors support it | Low–Med | S | Request |
| Kill switch **(M18)** | **Done** — `CredProx:KillSwitch` `Clusters`/`Callers` id lists, enforced at the new `Stage.ApplyKillSwitch` with `503 credprox.vendor_disabled` / `credprox.caller_disabled`; live on config reload, failed rebind keeps the previous switch state, section fail-closed like the rest | Medium | S | Request |

### 8.5 Observability, audit and operations

| Feature | Description | Value | Effort |
|---|---|---|---|
| Audit log with redaction **(in 0.3)** | Caller, vendor, method, path template, status, latency, bytes. Configurable header/JSON-field masking. Sink abstraction (ILogger, OTel logs, file) | High | M |
| Credential health monitoring **(in 0.3)** | Background check that tokens can still be obtained and certs are not near expiry. Health check + metric + log warning N days before expiry | High | S |
| Usage metering / chargeback | Request and byte counts per caller per vendor as OTel metrics | Medium | S |
| Error normalisation **(M24, Done)** | Vendor error bodies → RFC 7807 `ProblemDetails`, with a distinct `type` for proxy vs vendor failures — **Done**: default-on lossless rewrite (`vendor_detail`/`vendor_content_type` embed) after the scrubber, charset gate (absent/UTF-8/US-ASCII normalise, anything else byte-identical rather than re-encoded — quoted parameter values like charset="utf-8" count as anything else, since the gate matches the unquoted name; if that ever matters, strip matched quotes in the gate), cap with byte-identical over-cap pass-through, global and per-route opt-outs | Medium | M |
| Admin introspection endpoint | Routes, features, token status (expiry, last error) — **never** secret values. Behind an admin policy | Medium | S |

### 8.6 Developer experience

| Feature | Description | Value | Effort |
|---|---|---|---|
| Record/replay mode | Record real vendor responses (redacted) to fixtures, replay in dev/CI | Medium | M |
| Vendor presets | Community-contributed config snippets for common vendors (ADP, Workday, Salesforce, ServiceNow, GitHub Apps) | High (adoption) | S each |
| `dotnet new credprox` template | Minimal host + sample config | Medium | S |
| Fail-closed unknown-key validation for the remaining sections | **Done** — M14a (`CredProx:Callers`/`CallerAuth`), M16 (`CredProx:Credentials`, allowed keys = the options properties by reflection, preset layering included, plugins covered), M17 (`CredProx:Destinations`/`Connections` startup + reload; `Audit`/`Health`/`Throttling`/`Resilience` startup; the `CredProx` root rejects unknown keys and misspelled section names). Shared `ConfigKeyValidator`; every `CredProx:` key is now validated somewhere | Medium | S |
| Aspire integration | `AddCredProx()` resource for .NET Aspire AppHost | Low–Med | S |

### 8.7 Inbound-direction twin (optional)

| Feature | Description | Value | Effort |
|---|---|---|---|
| Webhook signature verification | Verify vendor webhooks (Stripe, GitHub, Shopify HMAC, etc.) on inbound routes before forwarding to internal services. Reuses the signing primitives from 8.1 | Medium | M |

### Suggested roadmap

Shipped releases drifted from the original theme buckets (each release took whatever
the person approved next), so the table records what actually shipped plus the forward
plan; §7 milestone rows stay the detailed record.

| Version | Theme | Contents |
|---|---|---|
| **0.3** (first public release) | Credential core, least privilege, operations, traffic, plugins | §4 scope (phases A–C), §5 tests, §6 examples E1–E11 |
| 0.4 | Presets removal | Built-in presets removed (breaking): every vendor an isolated explicit-config sample (M12); E13 AiGateway |
| 0.5 | Delegated | `TokenExchange` (M14/M14a), per-caller budgets (M15), `CredProx:Credentials` unknown-key fail-closed (M16); E14 TokenExchange |
| 0.6 | Least-privilege & agent batch | Remaining sections unknown-key fail-closed (M17), kill switch (M18), consent-required signalling (M19), response secret scrubbing incl. SSE event framing (M20/M22); E15 AgentEgress (M21) |
| 0.7 (next) | Vendor shapes | Session-cookie login with a generic successor to the original Cayuse demo (person-selected 2026-10-20; M23, E16 SessionCookie), vendor error normalisation with lossless `vendor_detail` embed and per-route opt-out (M24, §8.5) |
| later | Breadth | `CredProx.Aws` (SigV4), refresh-token grant, placeholder substitution, admin endpoint, metering, idempotency keys, community preset pack |
| 1.0 | Stable API | `[Experimental]` removed from plugin contract, package validation baseline locked, docs site, external security review |

---

## 9. Risks and open decisions

- **Security posture.** A credential broker is a high-value target. The library must make the safe
  path the default: allow-lists, header stripping, no secret logging, and validation at startup.
  Do a security self-review before the first release, an external review before 1.0, and publish `SECURITY.md` from the first preview.
- **Body buffering.** HMAC and SigV4 need the body; this conflicts with YARP streaming. Make
  buffering opt-in per route with a size cap.
- **Distributed token cache.** In-memory is fine per instance. Scale-out users may want a shared
  cache. Keep `ITokenCache` an interface and do not build a shared one yet.
- **Larger first release.** Going straight to the 0.3 scope delays outside feedback by about five
  weeks. Mitigation: the three phase previews on the Gitea registry, used by the HR integrations
  (E6) from preview 1 onward.
- **Plugin contract churn.** Opening the plugin API in the first release invites dependents before
  the contract is proven. Mitigation: `[Experimental]` until 1.0, and dogfooding every built-in.
- **CI capacity.** Container E2E and load tests need Docker on the runner (GitHub's
  ubuntu runners have it); nightly vendor smoke tests need vendor secrets stored as
  repository secrets.
- **Open decisions — all settled by the person on 2026-10-15 (M11 kickoff):**
  1. Credential failure status: **`502`**, as §3.4 already says. No code change.
  2. Public source host: **Gitea** (this instance). SourceLink and package repository URLs
     point at Gitea; a GitHub push comes later, outside M11.
     **Amended 2026-10-29 (M25): the source home is GitHub
     (`https://github.com/GravLabs/cred-prox`)** — package metadata, SourceLink and live
     links point there; the launch is a squashed clean-start snapshot (no full history);
     the internal Gitea repo stays the `origin` remote and the registry host.
  3. nuget.org: **postponed**. `0.3.0` publishes to the Gitea NuGet registry only.
     **Unchanged by M25:** the registry scope stays as-is (machine-local feed per
     PUBLISHING.md); nuget.org remains postponed.
  4. Version: **`0.3.0`**.
  5. The GitHub `yarp-proxy-custom-extensions` repo: the person will **decommission** it;
     not part of M11.

---

*Sources for the landscape section:* Duende BFF YARP docs (docs.duendesoftware.com/bff/fundamentals/apis/yarp),
Linbik.YARP (nuget.org/packages/Linbik.YARP), MuleSoft outbound OAuth / OBO credential injection policies
(docs.mulesoft.com/gateway), agentgateway credential brokering blog (agentgateway.dev, 2026-07-27),
Gravitee MCP credential brokering, Permit.io egress proxy credentials. YARP API surface verified against
`Yarp.ReverseProxy` 2.3.0 XML docs.
