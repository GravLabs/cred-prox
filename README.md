# CredProx

Outbound credential and policy brokering for third-party APIs, built on
[YARP](https://github.com/dotnet/yarp).

Callers send requests without secrets. CredProx attaches the right credential (OAuth tokens,
API keys, client certificates, signatures), enforces per-caller policy, and forwards the
request. Vendor integration is **configuration only**, with no vendor-specific C#.

**Built for AI agents and other short-lived workers.** An agent never holds a vendor secret,
and it doesn't need a long-lived CredProx secret either. It presents a short-lived Microsoft
Entra (or any OpenID Connect) access token, obtained through a managed identity or workload
identity federation, and Entra app roles narrow what it may call. See
[`samples/AgentTokens`](samples/AgentTokens) and
[ADR-0004](docs/adr/0004-short-lived-scoped-caller-tokens.md).

```csharp
// One call registers the core defaults: token cache, the configuration-backed secret
// source, the built-in credential types, and the credentials and destinations below.
// Chained calls bring in the add-on packages you need.
builder.Services.AddCredProx(builder.Configuration)
    .AddIdentity(); // CredProx.Identity — this config uses an OAuth type
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(); // the proxy pipeline, also from config
```

```json
{
  "CredProx": {
    "Credentials": {
      "graph": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token",
        "ClientId": "<app-client-id>",
        "Scope": "https://graph.microsoft.com/.default",
        "ClientSecret": "secret:graph-client-secret"
      }
    },
    "Secrets": { "graph-client-secret": "<app-client-secret>" }
  },
  "ReverseProxy": {
    "Routes": {
      "graph": {
        "ClusterId": "graph",
        "Match": { "Path": "/graph/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/graph" } ],
        "Metadata": { "CredProx.Credential": "graph" }
      }
    },
    "Clusters": {
      "graph": { "Destinations": { "graph": { "Address": "https://graph.microsoft.com/" } } }
    }
  }
}
```

A caller calls `/graph/v1.0/users` with no `Authorization` header; Microsoft Graph receives
an Entra access token that CredProx obtained, cached and refreshed.

## Start here

| If you want to… | Example |
|---|---|
| Give AI agents short-lived, scoped access with no stored secret (Entra) | [AgentTokens](samples/AgentTokens) |
| Put an AI agent's tool calls behind per-agent allow-lists | [AgentEgress](samples/AgentEgress) |
| Front an AI provider: caller keys in, provider key injected, streaming intact | [AiGateway](samples/AiGateway) |
| Reach an Azure OpenAI deployment with a short-lived Entra token and no API key, per-caller deployment allow-lists | [AzureOpenAI](samples/AzureOpenAI) |
| Call Microsoft Graph or any Entra-protected API, with a secret or secretless | [MicrosoftGraph](samples/MicrosoftGraph) |
| OAuth client credentials end to end (cache, single-flight, refresh) | [OAuthKeycloak](samples/OAuthKeycloak) |
| OAuth plus a client certificate on every hop (ADP shape) | [ADP](samples/ADP) |
| Exchange a user's token for a per-user downstream token | [TokenExchange](samples/TokenExchange) |
| Authenticate callers with API keys kept as config | [CallerApiKey](samples/CallerApiKey) |

Smallest possible host: [`samples/QuickStart`](samples/QuickStart). Every example, with
what it needs and how it is verified, is listed in [samples/README.md](samples/README.md).
Each vendor is one isolated sample with its full setup in plain config; the library ships
no built-in vendor presets.

## What's in the box

- **Credential types**: built-in `StaticKey`, `Hmac` and `LoginExchange` ship in the
  core; `TokenCredential` registers through the `CredProx.Azure` extension, and the
  three OAuth types (`OAuthClientCredentials`, `TokenExchange`, `JwtAssertion`) ship in
  `CredProx.Identity` — every vendor is plain config, and a
  community **preset** (`CredProx:Presets` or a custom `IPresetSource`) can package the
  fixed facts of a vendor so a credential is a few lines.
- **Token cache** with per-credential/per-partition scoping, single-flight refresh, early
  refresh, negative caching.
- **Secret sources** with per-credential scoping; `secret:` references validated at
  startup; Key Vault and other external stores plug in as a host-side `IConfiguration`
  provider (the Azure SDK's own is `src/CredProx.Azure/README.md`'s worked example).
- **Destinations & connections**: static or templated with fail-closed allow-lists;
  client certificates and mTLS per cluster, with reload.
- **Caller authentication**: short-lived Entra / OpenID Connect access tokens whose roles
  narrow the caller's rules, inbound API keys, per-caller vendor accounts, and fail-closed
  operation allow-lists.
- **Operations**: throttling with `Retry-After`, per-cluster retries/circuit breakers
  and credential health probes (the `CredProx.Operations` add-on), audit log with
  redaction and pluggable sinks.
- **Safety nets**: a per-vendor and per-caller **kill switch** by configuration alone,
  `401 credprox.consent_required` when a user still has to grant consent, and **response
  scrubbing** that removes an echoed credential before the caller sees it.
- **Plugins**: `CredProx.Abstractions` is the contract; `CredProx.Testing` ships the
  fakes and conformance suites the built-ins themselves are tested with.

## Vendors

[docs/vendors/](docs/vendors/) carries a copy-paste `CredProx:` config block per
vendor: [Microsoft Graph](docs/vendors/graph.md), [ADP](docs/vendors/adp.md),
[Workday](docs/vendors/workday.md), [Salesforce](docs/vendors/salesforce.md),
[ServiceNow](docs/vendors/servicenow.md), [GitHub Apps](docs/vendors/github-apps.md),
[OpenAI](docs/vendors/openai.md), [Slack](docs/vendors/slack.md),
[Stripe](docs/vendors/stripe.md), [Atlassian](docs/vendors/atlassian.md) and
[Google APIs](docs/vendors/google.md).
Each one covers the auth model, required secret names, scopes and gotchas.
Every block is bound and validated through the real
fail-closed startup path by a CI test, so a snippet with a wrong or misspelled key
fails the build, not your deploy. Facts are sample-traceable, cited to vendor docs,
or explicitly marked unverified. These are docs, not built-ins — the library still
ships no vendor presets.

## Packages

| Package | What it does | You need it when… |
|---|---|---|
| `CredProx` | The core: proxy pipeline, token cache, `secret:` references, the built-in `StaticKey` type, caller policy plumbing, audit — plus caller API keys, `Hmac` signing and `LoginExchange` as features that work from configuration alone | Every host — it is the host |
| `CredProx.Abstractions` | The public contracts (credential types, authenticators, secret sources, pipeline seams) | You write your own extension, or compile against the contract |
| `CredProx.Identity` | The `OAuthClientCredentials`, `TokenExchange` and `JwtAssertion` credential types, plus inbound caller authentication via short-lived Entra / OIDC access tokens, roles narrowing the caller's rules | The vendor speaks OAuth, or agents and other short-lived workers call you |
| `CredProx.Operations` | Throttling with `Retry-After`, per-cluster retries and circuit breakers, credential health probes | You run real traffic through it |
| `CredProx.Azure` | The `TokenCredential` credential type: trades an Azure token credential (managed identity, service principal) for Entra tokens | The vendor expects Entra tokens obtained through Azure identity |
| `CredProx.Testing` | Fakes and the conformance suites the built-ins themselves are tested with | You test a credential type or authenticator you wrote |

CredProx.CallerKeys, CredProx.Hmac and CredProx.LoginExchange (now in CredProx),
CredProx.OAuth and CredProx.CallerTokens (now CredProx.Identity) and
CredProx.AzureKeyVault (now CredProx.Azure) have been removed from the package
registry; reference the replacement package instead.

Install with `dotnet add package CredProx` plus the add-on packages you need; every
package targets `net10.0`. Until the first public nuget.org release lands (M44
readiness, PUBLISHING.md), the packages are served from the CredProx NuGet registry —
the feed is machine-local; publishing machines declare it in their user-level NuGet
config. Each package's own README carries its install line, its one registration call
and the config it reads; the core's README is also the package map that ships inside
the nupkg. See [CHANGELOG.md](CHANGELOG.md).

## Requirements and compatibility

.NET 10 only — `net8.0`/`net9.0` consumers get an exact `NU1202` refusal at
restore, not a surprise at runtime. Host shapes, dependency drift, container
publish, trimming/AOT and the `CredProx.Testing` consumer story are measured,
not assumed: see [docs/consumer-compatibility.md](docs/consumer-compatibility.md)
and `scripts/consumer-compat.sh`. Trimming and NativeAOT are **not supported**
yet; the standard DI-based proxy setup is warning-clean under
`-warnaserror` without suppression.

## Status

Pre-1.0 and actively developed. The [CHANGELOG](CHANGELOG.md) is the source of truth for the
current version, what changed and any migration steps; read it before upgrading across a
minor version. The public API is stable within a minor version (`0.x.*`). APIs marked
`[Experimental]` may change before 1.0, and that covers the caller-authentication plugin
points.

## Security

- Report vulnerabilities per [SECURITY.md](SECURITY.md).
- **Caller API keys must be high-entropy random values** (128+ bits). The caller registry
  stores them as **unsalted SHA-256 hashes** — a lookup index, not a password store.
  Generate keys with a CSPRNG and rotate by adding a key entry and retiring the old one.
- Audit records carry credential **names**, never values; redacted headers/JSON fields
  are masked before any sink sees them. Caller key values never appear in audit records
  or in CredProx log messages.
- **Response scrubbing inspects text-like bodies.** A response whose media type is
  `application/octet-stream` or another non-text type, that carries no media type,
  that arrives with an unknown or chained `Content-Encoding`, or whose declared
  charset the matcher cannot read (the `utf-16`/`utf-32` family, a stateful name like
  `iso-2022-jp`, or an unknown name — the readable ASCII-compatible charsets `utf-8`/`utf8`,
  `us-ascii`/`ascii`, `iso-8859-1` through `iso-8859-11` and `iso-8859-13` through
  `iso-8859-16` (there is no iso-8859-12), and `windows-1250` through `windows-1258`,
  matched by exact published name, are inspected like any other body) is
  forwarded byte-identical — an echoed credential inside such a body reaches the
  caller, and an event-stream boundary can split an echo across events; each class
  logs one warning per route. The matcher reads UTF-8/ASCII bytes: a secret that
  contains non-ASCII characters is matched only in its UTF-8 bytes. Alias spellings such as
  latin1, l1, iso8859-1 and cp1252 are not on the readable list. With the fail-closed option
  they are refused; in the default mode their bytes are searched as-is, which finds a plain
  ASCII echo but is not guaranteed. Declare the canonical name. The gate reads the DECLARED
  charset, never the bytes: a response that misreports its charset is not detected.
  `CredProx:Scrubbing:FailClosed=true`
  (default `false`) refuses those responses instead of forwarding them: a
  `credprox.response_uninspectable` problem response replaces the body, a refused
  success or redirect is answered `502`, and a vendor 4xx/5xx keeps its status; a
  refusal logs one warning that says the body was refused, naming the class and the
  route. A response with no body — an empty body, a `HEAD` response, a bodiless
  redirect — is never refused (a declared non-zero `Content-Length` counts as a
  body except on a `HEAD`, where the method alone decides), so redirects keep working with the option on. `FailClosed` requires
  `CredProx:Scrubbing:Enabled=true`; the combination with scrubbing off is rejected
  at startup.
- **The caller's own `Authorization` and `Cookie` do not ride to the vendor.** Header
  hygiene removes them — alongside the presented credential, the caller-auth key and
  the partition header — on every route; the credential CredProx itself attaches fills
  the vendor's `Authorization` slot after the strip, and the caller's other headers
  flow unchanged. A route that genuinely needs the caller's own `Authorization` or
  `Cookie` opts out with route metadata `CredProx.CallerHeaderStrip = "off"`; YARP's
  `RequestHeaderRemove` transform (one entry per header) remains the opposite door —
  both proven end-to-end in the test host.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) — build, tests, coverage gates. To write your own
credential type, authenticator or secret source, start with
[docs/extending.md](docs/extending.md); presets and plugins are welcome.

## License

MIT
