# CredProx.Azure

Azure add-on for [CredProx](https://github.com/GravLabs/cred-prox) — renamed from
`CredProx.AzureKeyVault` at 0.15.0 (ADR-0007): the package holds only the
`TokenCredential` credential type, never Key Vault code:

- **The `TokenCredential` credential type** — Azure AD tokens via `Azure.Identity`
  (managed identity, service principal, workload identity): a credential style with **no
  stored secret** at all. This package registers that one type; the core keeps no Azure
  knowledge beyond the startup hint that names this package.

**Redirects:** CredProx's redirect refusals do not cover Azure's own transports — neither
`Azure.Identity`'s token fetch nor a Key Vault `SecretClient` passes through a CredProx
guard (measured: both follow a cross-host 302 by default), so where that door must stay
shut, give each transport a primary handler with `AllowAutoRedirect = false`.

## Setup

```csharp
// Configuration once, then this package's one chained call — the credential type,
// fed any Azure token credential:
builder.Services.AddCredProx(builder.Configuration)
    .AddAzure(new DefaultAzureCredential());
```

A credential entry uses `Type: TokenCredential` with `Scope` and the optional
`TokenTypeName` (default `Bearer`) — see the
[`MicrosoftGraph` sample](https://github.com/GravLabs/cred-prox/tree/main/samples/MicrosoftGraph),
which runs both the secret-based and secretless styles against Microsoft Graph.

## Host pattern: Key Vault feeding the config

`secret:` references resolve against the host's configuration — so the common way to
keep vendor secrets out of config files entirely is the **standard Azure Key Vault
configuration provider** on the host, before `AddCredProx` reads config. Both
[`MicrosoftGraph`](https://github.com/GravLabs/cred-prox/tree/main/samples/MicrosoftGraph)
and [`AzureContainerApps`](https://github.com/GravLabs/cred-prox/tree/main/samples/AzureContainerApps)
do exactly that; none of it lives in this package:

```csharp
var keyVaultUri = builder.Configuration["KeyVault:Uri"];
if (!string.IsNullOrEmpty(keyVaultUri))
{
    builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), new DefaultAzureCredential(),
        new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(30) });
}
```

Two measured caveats about rotation, from live runs (2026-11-06):

- **Reload is necessary but not sufficient for rotated signing.** `secret:` values are
  read live at each credential MINT, but an assertion is minted only when the *exchanged
  access token* refreshes — never per request. End-to-end staleness of rotated signing
  material is bounded by the token cache, not by the reload interval:
  `lifetime × TokenCacheOptions.RefreshFraction` (default `0.8`), or `expiresAt − Skew`
  if that comes first. A rotation with a 59-minute token changes what a long-running
  proxy signs only after ~47 minutes even with a 30-second `ReloadInterval`. Size
  rotation drills and incident key-cutoff expectations against the MINT cadence — if the
  next request must reflect a rotation, that is an eviction/lifetime design, not a
  faster poller.
- **Vault secret names are configuration keys.** The configuration provider injects
  every secret name in the vault into the host's configuration — every config consumer
  sees them, not just CredProx. Hosts with strict fail-closed validation (rejecting
  unknown keys under a product prefix, for example) must tolerate foreign names, or
  keep non-product material out of the product namespace.

## Install

```bash
dotnet add package CredProx.Azure
```

Installs beside `CredProx`; the core package README carries the package map.

## License

MIT
