# MicrosoftGraph: two Entra credential styles, and Key Vault as the secret source

The same Graph endpoint reached with two different credential styles, from one host:

1. **Entra app client credentials** — the classic app registration + secret, spelled out
   in explicit config (`OAuthClientCredentials`, the `/.default` scope, Basic client auth).
2. **No stored secret at all** — the `TokenCredential` credential type from the
   `CredProx.Azure` add-on (the chained `.AddAzure(credential)`): tokens are minted by the ambient Azure identity (a
   user-assigned managed identity in Azure, the Azure CLI during development). Nothing to
   rotate because nothing is stored.

The style is pure config: `ASPNETCORE_ENVIRONMENT=OAuth` loads
`appsettings.OAuth.json`, `=ManagedIdentity` loads `appsettings.ManagedIdentity.json`.
`Program.cs` registers both credential add-ons unconditionally — a registered but unused
credential type is harmless — so the host you deploy is the host you ran today.

Plus **Key Vault as the secret source** for the first style — via the ordinary Azure
configuration provider, which is all CredProx's `secret:` references need.

**Packages:** `CredProx`, `CredProx.Identity`, `CredProx.Azure`, `Azure.Identity`
(and `Azure.Extensions.AspNetCore.Configuration.Secrets` for the Key Vault config source).

## Run it — client credentials

```bash
# Entra ID → App registrations → New registration → Certificates & secrets → New client secret
export ASPNETCORE_ENVIRONMENT=OAuth
export CredProx__Credentials__graph__TokenEndpoint="https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token"
export CredProx__Credentials__graph__ClientId=<application id>
env 'CredProx__Secrets__graph-client-secret=<client secret value>' \
  dotnet run --project samples/MicrosoftGraph
```

The secret is delivered with `env '...'`, not `export`: bash's `export` refuses names
containing hyphens ("not a valid identifier"), while .NET reads such variables fine.
(In development: `dotnet user-secrets --project samples/MicrosoftGraph set
'CredProx:Secrets:graph-client-secret' '<client secret value>'`.)

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
export ASPNETCORE_ENVIRONMENT=ManagedIdentity
export AZURE_CLIENT_ID=<identity client id>     # DefaultAzureCredential picks these up
export AZURE_TENANT_ID=<tenant id>
dotnet run --project samples/MicrosoftGraph
```

Each style declares its credential in its own file, and each file declares only the keys
its credential `Type` owns — CredProx rejects keys the active type does not declare, so
the styles cannot be layered on one another. The managed-identity style's whole credential:

```jsonc
"graph": {
  "Type": "TokenCredential",
  "Scope": "https://graph.microsoft.com/.default"
}
```

On an Azure Container App or VM with the identity attached, even the two `AZURE_*`
variables disappear — `DefaultAzureCredential` finds the platform identity on its own.

## Key Vault as the secret source

CredProx resolves `secret:` references through `IConfiguration`, so the standard Key Vault
configuration provider *is* the integration — already referenced by this sample and wired
behind `KeyVault:Uri`:

```bash
az keyvault secret set --vault-name <vault> --name "CredProx--Secrets--graph-client-secret" \
  --value "<client secret value>"
export KeyVault__Uri=https://<vault>.vault.azure.net/   # or --KeyVault:Uri ...
```

Drop the `env 'CredProx__Secrets__graph-client-secret=...'` wrapper and the same
`secret:graph-client-secret` reference the credential declares now resolves from the vault —
secret material enters the process only from the vault, and the caller's identity (here the
az CLI sign-in) needs *Key Vault Secrets User* on it. Rotation: overwrite the vault secret
with `az keyvault secret set` again; the next process start picks up the new value. A
rotated vault value reaches a *running* process only because `AddAzureKeyVault` is called
with `ReloadInterval` set — this sample sets it to 30s; the provider default never polls.
Without it (or a restart), the old value is served forever.
`scripts/live-azure-smoke.sh 4` proves this overwrite -> restart -> new-value cycle
against a real vault.

## The exact config (client-credentials style)

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
before the first request. Run the host with no style file and the placeholders untouched
and it names every missing value and exits instead of serving traffic half-configured.

## What just happened

Tracing `curl http://localhost:5085/graph/v1.0/users?$top=1`:

1. The route strips `/graph` and names credential `graph`.
2. Client-credentials style: CredProx POSTs the client-credentials grant to the tenant's
   token endpoint with scope `…/.default` and caches the app token. Managed-identity
   style: the `TokenCredential` type asks `DefaultAzureCredential` for a Graph token — no
   endpoint, no secret, no form post.
3. Either way the forwarded request carries `Authorization: Bearer <app token>` to
   `graph.microsoft.com`, which authorizes it against the app's granted permissions.
4. The caller — and the app's own code — never held the secret or the identity's
   credentials. And if a vendor response echoes a token back, CredProx's scrubber replaces
   it with `[redacted]` in the bytes flowing to the caller: a credential never leaks into
   a response body.

## Verify it (offline)

No Azure account needed: a WireMock stand-in plays Entra ID's token endpoint and Graph
itself (`wiremock/mappings/`, needs Docker). The cells drive the real host:

```bash
dotnet test tests/CredProx.SampleSmokes --filter Sample=MicrosoftGraph
# or the one-line wrapper:
cd samples/MicrosoftGraph && ./smoke.sh
```

The cells: the placeholder run refuses to start and names every missing value plus the
pointer to this file; the no-style run refuses with the same guidance; the full
client-credentials run takes a token from the stub once, calls Graph twice on one cached
token, the vendor's journal shows the real `Bearer` token while the caller-side echo shows
`[redacted]`.

The managed-identity style is not cellable offline — Azure Identity refuses any authority
that is not a real cloud endpoint — so it is covered by `scripts/live-azure-smoke.sh`
against live Azure instead.
