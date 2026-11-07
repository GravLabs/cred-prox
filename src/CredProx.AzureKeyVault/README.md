# CredProx.AzureKeyVault

Azure add-on for [CredProx](https://github.com/GravLabs/cred-prox):

- **Key Vault as a secret source** — `secret:` references resolve through Azure Key
  Vault, so vendor client secrets never sit in configuration. A rotated vault value
  reaches a running process only because `AddAzureKeyVault` is called with
  `ReloadInterval` set; the provider default never polls. Without it (or a restart),
  the old value is served forever.

  **Reload is necessary but not sufficient for rotated signing.** `secret:` values
  are read live at each credential MINT, but an assertion is minted only when the
  *exchanged access token* refreshes — never per request. End-to-end staleness of
  rotated signing material is therefore bounded by the token cache, not by the
  reload interval: `lifetime × TokenCacheOptions.RefreshFraction` (default `0.8`),
  or `expiresAt − Skew` if that comes first. A rotation with a 59-minute token
  changes what a long-running proxy signs only after ~47 minutes even with a 30-second
  `ReloadInterval` (live-verified 2026-11-06, M29 P10). Size rotation drills,
  incident key-cutoff expectations, and tests against the MINT cadence — if you need
  the next request to reflect a rotation, that is an eviction/lifetime design, not a
  faster poller.
  **Vault secret names are configuration keys.** The provider injects every
  secret name in the vault into the host's configuration — every config
  consumer sees them, not just CredProx. Hosts with strict fail-closed
  validation (rejecting unknown keys under a product prefix, for example) must
  tolerate foreign names, or keep non-product material out of the product
  namespace: this sample's public pinning material is deliberately named
  `CredProxTest--…`, not `CredProx--…` (live finding 2026-11-06).
- **`TokenCredential` credential type** — Azure AD tokens via `Azure.Identity`
  (managed identity, service principal, workload identity): a credential style with **no
  stored secret** at all.

## Setup

```csharp
builder.Services.AddCredProxAzureTokenCredential();
```

Point CredProx's secret source at Key Vault through configuration (see the
[`MicrosoftGraph` sample](https://github.com/GravLabs/cred-prox/tree/main/samples/MicrosoftGraph),
which runs both credential styles against Microsoft Graph and uses Key Vault as the
secret source).

## License

MIT
