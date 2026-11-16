# CredProx

Outbound credential and policy brokering for third-party APIs, built on
[YARP](https://github.com/dotnet/yarp). Callers send requests **without secrets**;
CredProx attaches the right credential, enforces per-caller policy, and forwards the
request. Everything a vendor integration needs is **configuration** — no vendor-specific C#.

This is the core package: credential providers, token cache, secret sources, destinations
and connections (mTLS), caller authentication, throttling and resilience, presets, audit
and health.

## Quick start

```csharp
builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);
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
an Entra access token. Built-in credential types: `OAuthClientCredentials`, `LoginExchange`,
`StaticKey`, `TokenCredential`, `JwtAssertion`, `Hmac`. The library ships no built-in
vendor presets — every vendor is shown as explicit config in its own
[sample](https://github.com/GravLabs/cred-prox/tree/main/samples); a community preset
under `CredProx:Presets` (or a custom `IPresetSource`) can package a vendor's fixed facts
so a credential is a few lines.

## Packages

| Package | Purpose |
|---|---|
| `CredProx` | this one — the core |
| `CredProx.Abstractions` | the plugin contract (implement to write credential-type plugins) |
| `CredProx.AzureKeyVault` | Key Vault secret source + `TokenCredential` |
| `CredProx.Testing` | fakes + conformance suites for plugin authors |

Samples live in [`samples/`](https://github.com/GravLabs/cred-prox/tree/main/samples)
in the repository; the design and failure semantics are in
[`docs/credprox-plan.md`](https://github.com/GravLabs/cred-prox/blob/main/docs/credprox-plan.md).

## Status

`0.x` — the public API is stable within a minor version (`0.x.*`); APIs marked
`[Experimental]` may change before 1.0. Target framework: `net10.0`.

## License

MIT
