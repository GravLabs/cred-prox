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
builder.Services.AddCredProx(builder.Configuration);
builder.Services.AddCredProxOAuth(); // add-on calls for what you need (this config uses an OAuth type)
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration); // the proxy pipeline, also from config
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

- **Credential types**: built-in `StaticKey` (`TokenCredential` registers through the
  `CredProx.AzureKeyVault` extension), plus `Hmac`, `LoginExchange` and the three OAuth
  types (`OAuthClientCredentials`, `TokenExchange`, `JwtAssertion`) in their own
  packages (`CredProx.Hmac`, `CredProx.LoginExchange`,
  `CredProx.OAuth`) — every vendor is plain config, and a
  community **preset** (`CredProx:Presets` or a custom `IPresetSource`) can package the
  fixed facts of a vendor so a credential is a few lines.
- **Token cache** with per-credential/per-partition scoping, single-flight refresh, early
  refresh, negative caching.
- **Secret sources** with per-credential scoping; `secret:` references validated at
  startup; Azure Key Vault add-on.
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
[ServiceNow](docs/vendors/servicenow.md) and [GitHub Apps](docs/vendors/github-apps.md).
Each one covers the auth model, required secret names, scopes and gotchas.
Every block is bound and validated through the real
fail-closed startup path by a CI test, so a snippet with a wrong or misspelled key
fails the build, not your deploy. Facts are sample-traceable, cited to vendor docs,
or explicitly marked unverified. These are docs, not built-ins — the library still
ships no vendor presets.

## Packages

| Package | What it does | You need it when… |
|---|---|---|
| `CredProx` | The core: proxy pipeline, token cache, `secret:` references, the built-in `StaticKey` type, caller policy plumbing, audit | Every host — it is the host |
| `CredProx.Abstractions` | The public contracts (credential types, authenticators, secret sources, pipeline seams) | You write your own extension, or compile against the contract |
| `CredProx.CallerKeys` | Inbound caller authentication against API keys kept in config as SHA-256 hashes | Callers authenticate with static keys |
| `CredProx.CallerTokens` | Inbound caller authentication via short-lived Entra / OIDC access tokens, roles narrowing the caller's rules | Agents or other short-lived workers call you |
| `CredProx.OAuth` | The `OAuthClientCredentials`, `TokenExchange` and `JwtAssertion` credential types | The vendor speaks OAuth |
| `CredProx.Hmac` | The `Hmac` request-signing credential type | The vendor expects signed requests |
| `CredProx.LoginExchange` | The `LoginExchange` credential type: a form login whose session is replayed and refreshed | The vendor authenticates through a login endpoint |
| `CredProx.Operations` | Throttling with `Retry-After`, per-cluster retries and circuit breakers, credential health probes | You run real traffic through it |
| `CredProx.AzureKeyVault` | The `TokenCredential` credential type: trades an Azure token credential (managed identity, service principal) for Entra tokens | The vendor expects Entra tokens obtained through Azure identity |
| `CredProx.Testing` | Fakes and the conformance suites the built-ins themselves are tested with | You test a credential type or authenticator you wrote |

Published to the CredProx NuGet registry (the feed is machine-local; publishing
machines declare it in their user-level NuGet config — see PUBLISHING.md). Target
framework: `net10.0`. Each package's own README carries its one registration call and
the config it reads; the core's README is also the package map that ships inside the
nupkg. See [CHANGELOG.md](CHANGELOG.md).

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

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) — build, tests, coverage gates. To write your own
credential type, authenticator or secret source, start with
[docs/extending.md](docs/extending.md); presets and plugins are welcome.

## License

MIT
