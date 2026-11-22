# CredProx

Outbound credential and policy brokering for third-party APIs, built on
[YARP](https://github.com/dotnet/yarp). Callers send requests **without secrets**;
CredProx attaches the right credential, enforces per-caller policy, and forwards the
request. Everything a vendor integration needs is **configuration** — no vendor-specific C#.

This is the core package: credential providers, token cache, secret sources, destinations
and connections (mTLS), the caller-policy plumbing, presets, audit, and the pipeline
seams — caller API keys included, armed straight from `CredProx:Callers`. Throttling,
resilience and credential health probes are the `CredProx.Operations` add-on; the
OAuth-based credential types and inbound caller tokens are the `CredProx.Identity` add-on.

## Quick start

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

A caller then calls `/graph/v1.0/users` with no `Authorization` header; Microsoft Graph receives
an Entra access token. Built-in credential types: `StaticKey`, `Hmac` and
`LoginExchange` ship in the core; `TokenCredential` arrives with `CredProx.Azure`'s
chained `.AddAzure(credential)`, and the OAuth-based types — `OAuthClientCredentials`,
`TokenExchange`, `JwtAssertion` — ship in `CredProx.Identity`, where you reference the
package and chain its `.AddIdentity()`. The library ships no built-in
vendor presets — every vendor is shown as explicit config in its own
[sample](https://github.com/GravLabs/cred-prox/tree/main/samples); a community preset
under `CredProx:Presets` (or a custom `IPresetSource`) can package a vendor's fixed facts
so a credential is a few lines.

## Packages

| Package | Purpose |
|---|---|
| `CredProx` | this one — the core host pieces every add-on plugs into, plus caller API keys, `Hmac` signing and `LoginExchange`: core features that work from configuration alone |
| `CredProx.Abstractions` | the public contracts (credential types, authenticators, secret sources, pipeline seams) |
| `CredProx.Azure` | the `TokenCredential` credential type (Entra tokens via `Azure.Identity`, no stored secret) |
| `CredProx.Identity` | the `OAuthClientCredentials`, `TokenExchange` and `JwtAssertion` credential types, plus inbound caller authentication via short-lived Entra / OIDC access tokens with roles narrowing the caller's rules |
| `CredProx.Operations` | throttling with `Retry-After`, per-cluster retries and circuit breakers, credential health probes |
| `CredProx.Testing` | fakes + the conformance suites the built-ins themselves are tested with |

Samples live in [`samples/`](https://github.com/GravLabs/cred-prox/tree/main/samples)
in the repository.

## Extension points

Everything the built-ins use is open to your package — the contracts ship in
`CredProx.Abstractions`, the registration calls live in `CredProx`, and
[`docs/extending.md`](https://github.com/GravLabs/cred-prox/blob/main/docs/extending.md)
is the full guide:

- **Caller authenticator** (`ICallerAuthenticator`, `WithCallerAuthenticator<T>()` on the
  builder): turns inbound request material into an authenticated caller; registering one
  brings the caller policy pipeline with it.
- **Registry validator** (`ICallerRegistryValidator`, `WithCallerRegistryValidator<T>()`):
  a fail-closed startup check over the built caller registry.
- **Registry contributor** (`ICallerRegistryContributor`, `WithCallerRegistryContributor<T>()`):
  builds part of the caller registry from your own source, generation-tracked like the
  built-in one.
- **Credential type** (`ICredentialProvider<TOptions>`, `WithCredentialType<TProvider, TOptions>(typeName)`):
  a way to obtain and attach a credential for a named config entry.
- **Secret source and secret-reference resolution** (`ISecretSource`, `ISecretAccessor`):
  resolves `secret:` references; unresolvable references refuse startup.
- **Pipeline feature and stage order** (`IPipelineFeature` and the request/connection/response
  flavours): cross-cutting behavior per proxied request, executed in a fixed stage order.
- **The body hand-off** (`CredProxRequestState`): the measured-body seam for features
  that need the whole outbound body, with a byte cap — how the signing stage gets its bytes.

## Status

`0.x` — the public API is stable within a minor version (`0.x.*`); APIs marked
`[Experimental]` may change before 1.0. Target framework: `net10.0`.

## Install

```bash
dotnet add package CredProx
```

Add-on packages install under their own ids (`dotnet add package CredProx.Identity`, and
so on) and register with one call each; the Packages section above is the map.

## License

MIT
