# CredProx

Outbound credential and policy brokering for third-party APIs, built on
[YARP](https://github.com/dotnet/yarp).

Callers send requests without secrets. CredProx attaches the right credential (OAuth tokens,
API keys, client certificates, signatures), enforces per-caller policy, and forwards the
request. Vendor integration is **configuration only** — no vendor-specific C#.

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
      "spotify": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "https://accounts.spotify.com/api/token",
        "ClientId": "<app-client-id>",
        "ClientSecret": "secret:spotify-client-secret",
        "ClientAuthentication": "BasicHeader"
      }
    },
    "Secrets": { "spotify-client-secret": "<app-client-secret>" }
  },
  "ReverseProxy": {
    "Routes": {
      "spotify": {
        "ClusterId": "spotify",
        "Match": { "Path": "/spotify/{**catch-all}" },
        "Metadata": { "CredProx.Credential": "spotify" }
      }
    }
  }
}
```

A caller calls `/spotify/...` with no `Authorization` header; the vendor receives the OAuth
token. Start with [`samples/QuickStart`](samples/QuickStart) — fourteen samples (E1–E14,
[samples/README.md](samples/README.md)) cover OAuth client credentials, mTLS, login
exchanges with per-environment partitions, per-caller credentials, token exchange for
per-user downstream credentials, GitHub App, HMAC signing, custom plugins and operations
under load. Each vendor — Spotify, Microsoft Graph,
ADP, GitHub App, Keycloak — is one isolated sample with its full setup spelled out in
plain config; the library ships no built-in vendor presets.

## What's in the box

- **Credential types**: `OAuthClientCredentials`, `LoginExchange`, `StaticKey`,
  `TokenCredential`, `JwtAssertion`, `Hmac` — every vendor is plain config, and a
  community **preset** (`CredProx:Presets` or a custom `IPresetSource`) can package the
  fixed facts of a vendor so a credential is a few lines.
- **Token cache** with per-credential/per-partition scoping, single-flight refresh, early
  refresh, negative caching.
- **Secret sources** with per-credential scoping; `secret:` references validated at
  startup; Azure Key Vault add-on.
- **Destinations & connections**: static or templated with fail-closed allow-lists;
  client certificates and mTLS per cluster, with reload.
- **Caller authentication**: inbound API keys, per-caller vendor accounts, fail-closed
  operation allow-lists.
- **Operations**: throttling with `Retry-After`, per-cluster retries/circuit breakers,
  credential health probes, audit log with redaction and pluggable sinks.
- **Plugins**: `CredProx.Abstractions` is the contract; `CredProx.Testing` ships the
  fakes and conformance suites the built-ins themselves are tested with.

## Packages

`CredProx`, `CredProx.Abstractions`, `CredProx.AzureKeyVault`, `CredProx.Testing` —
published to the CredProx NuGet registry (the feed is machine-local; publishing
machines declare it in their user-level NuGet config — see PUBLISHING.md). Target
framework: `net10.0`. See [CHANGELOG.md](CHANGELOG.md).

## Status

**0.6.0** — kill switch (take a cluster or caller out of service by config, live on reload),
consent-required signalling, and response secret scrubbing: any credential value the
pipeline injects is removed when the upstream reflects it back, with `text/event-stream`
scrubbed per event so streaming latency survives (breaking config: list entries under
`CredProx` sections must now be indexed, and unknown keys in the remaining sections refuse
startup — see the [CHANGELOG](CHANGELOG.md) migration notes). Example E15 `samples/AgentEgress`
shows the AI-agent egress shape. The public API is stable within `0.6.x`; APIs marked
`[Experimental]` may change before 1.0.

## Security

- Report vulnerabilities per [SECURITY.md](SECURITY.md).
- **Caller API keys must be high-entropy random values** (128+ bits). The caller registry
  stores them as **unsalted SHA-256 hashes** — a lookup index, not a password store.
  Generate keys with a CSPRNG and rotate by adding a key entry and retiring the old one.
- Audit records carry credential **names**, never values; redacted headers/JSON fields
  are masked before any sink sees them. Caller key values never appear in audit records
  or in CredProx log messages.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) — build, tests, coverage gates, and how to contribute
presets and credential-type plugins.

## License

MIT
