# E5 — MicrosoftGraph: two credential styles, and Key Vault as the secret source

## What it demonstrates

The same Graph endpoint reached with two different credential styles:

1. **Entra app client credentials** — the classic app registration + secret, spelled out
   in explicit config (`OAuthClientCredentials`, the `/.default` scope, Basic client auth)
   plus the tenant endpoint and Client ID the host owns.
2. **No stored secret at all** — `--variant identity` swaps in the `TokenCredential`
   credential type from the `CredProx.AzureKeyVault` add-on: tokens are minted by the
   ambient Azure identity (a user-assigned managed identity in Azure, the Azure CLI during
   development). Nothing to rotate because nothing is stored.

Plus **Key Vault as the secret source** for the first style — via the ordinary Azure
configuration provider, which is all CredProx's `secret:` references need.

## What you need

- Client-credentials variant: an Entra tenant with an app registration (free).
- Managed-identity variant: an Azure user-assigned managed identity (or just `az login`
  locally — `DefaultAzureCredential` picks up the CLI).

## Run it — client credentials

```bash
# Entra ID → App registrations → New registration → Certificates & secrets → New client secret
export CredProx__Credentials__graph__TokenEndpoint="https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token"
export CredProx__Credentials__graph__ClientId=<application id>
export CredProx__Secrets__graph-client-secret=<client secret value>
dotnet run --project samples/MicrosoftGraph
```

Grant the app the **`User.Read.All`** *application* permission (API permissions →
Application → User.Read.All → Grant admin consent). Then, **no credential in the request**:

```bash
curl -s "http://localhost:5085/graph/v1.0/users?\$top=1" | head -c 400
```

A Graph directory-objects response comes back; Graph saw an app token CredProx fetched from
`login.microsoftonline.com` with the `https://graph.microsoft.com/.default` scope.

## Run it — managed identity (no secret)

```bash
az identity create -g <rg> -n credprox-demo     # or any user-assigned managed identity
# give that identity User.Read.All app permission on Microsoft Graph, then:
export AZURE_CLIENT_ID=<identity client id>     # DefaultAzureCredential picks these up
export AZURE_TENANT_ID=<tenant id>
dotnet run --project samples/MicrosoftGraph -- --variant identity
```

Each variant declares its credential in its own file — `appsettings.OAuth.json` for the
client-credentials run, `appsettings.ManagedIdentity.json` for `--variant identity` —
because CredProx rejects keys the active credential `Type` does not declare. The identity
variant's whole credential is:

```jsonc
"graph": {
  "Type": "TokenCredential",
  "Scope": "https://graph.microsoft.com/.default"
}
```

and `Program.cs` registers the ambient credential once:
`AddCredProxAzureTokenCredential(new DefaultAzureCredential())`. On an Azure Container App
or VM with the identity attached, even the two `AZURE_*` variables disappear.

## Key Vault as the secret source

CredProx resolves `secret:` references through `IConfiguration`, so the standard Key Vault
configuration provider *is* the integration — one line in `Program.cs` (commented in the
source):

```bash
dotnet add package Azure.Extensions.AspNetCore.Configuration.Secrets
az keyvault secret set --vault-name <vault> --name "CredProx--Secrets--graph-client-secret" \
  --value "<client secret value>"
```

Uncomment the `AddAzureKeyVault` line, drop the `CredProx__Secrets__graph-client-secret`
environment variable, and the same `secret:graph-client-secret` reference the credential
declares now resolves from the vault. (The dedicated Key Vault secret *source* ships in the
`CredProx.AzureKeyVault` add-on in a later milestone; this is the path that works today.)

## The exact config (client-credentials variant)

```jsonc
"CredProx": {
  "Destinations": { "graph": { "Template": "https://graph.microsoft.com" } },
  "Credentials": {
    "graph": {
      "Type": "OAuthClientCredentials",
      "TokenEndpoint": "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token",
      "ClientId": "",
      "Scope": "https://graph.microsoft.com/.default",
      "ClientAuthentication": "BasicHeader",
      "ClientSecret": "secret:graph-client-secret"
    }
  },
  "Secrets": { "graph-client-secret": "" }   // value from env, user-secrets, or Key Vault
}
```

Every `secret:` reference a credential declares — here `secret:graph-client-secret` — is
validated against the host's secret sources at startup; an unresolvable one fails startup
before the first request.

## What just happened

Tracing `curl http://localhost:5085/graph/v1.0/users?$top=1`:

1. The route strips `/graph` and names credential `graph`.
2. Client-credentials variant: CredProx POSTs the client-credentials grant to the tenant's
   `token` endpoint with scope `…/.default` and caches the app token.
   Managed-identity variant: the `TokenCredential` type asks `DefaultAzureCredential` for a
   Graph token — no endpoint, no secret, no form post.
3. Either way the forwarded request carries `Authorization: Bearer <app token>` to
   `graph.microsoft.com`, which authorizes it against the app's granted permissions.
4. The caller — and the app's own code — never held the secret or the identity's
   credentials.
