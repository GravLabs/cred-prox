# CredProx.AzureKeyVault

Azure add-on for [CredProx](https://github.com/GravLabs/cred-prox):

- **Key Vault as a secret source** — `secret:` references resolve through Azure Key
  Vault, so vendor client secrets never sit in configuration.
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
