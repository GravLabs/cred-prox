# Microsoft Graph (Entra ID)

| | |
|---|---|
| **Auth model** | Entra ID OAuth 2.0 client credentials per tenant; Graph then takes the bearer token. App permissions require admin consent — the consent-free M26 validation set deliberately used Azure RBAC targets instead ([docs/live-validation-report.md](../live-validation-report.md)) |
| **CredProx credential** | `OAuthClientCredentials` with `ClientAuthentication: BasicHeader` — **or** secretless `TokenCredential` (ambient Azure identity) |
| **Sample** | [E5 `samples/MicrosoftGraph`](../../samples/MicrosoftGraph/README.md) — both variants, plus Key Vault as the secret source |
| **Verification** | Endpoint form, `.default` scope and Basic client auth verified in sample E5 (`appsettings.OAuth.json` / `appsettings.ManagedIdentity.json`); the live Entra and Key Vault paths were validated against the person's tenant in M26 ([report](../live-validation-report.md)) |

## CredProx config

Client-credentials variant (works anywhere; needs a tenant + app secret):

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "graph": { "Template": "https://graph.microsoft.com" }
    },
    "Credentials": {
      "graph": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token",
        "ClientId": "<your-app-client-id>",
        "ClientAuthentication": "BasicHeader",
        "ClientSecret": "secret:graph-client-secret",
        "Scope": "https://graph.microsoft.com/.default"
      }
    },
    "Secrets": {
      "graph-client-secret": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "graph": {
        "ClusterId": "graph",
        "Match": { "Path": "/graph/{**catch-all}" },
        "Transforms": [
          { "PathRemovePrefix": "/graph" }
        ],
        "Metadata": {
          "CredProx.Destination": "graph",
          "CredProx.Credential": "graph"
        }
      }
    },
    "Clusters": {
      "graph": {
        "Destinations": {
          "graph": { "Address": "https://graph.microsoft.com/" }
        }
      }
    }
  }
}
```

Running on Azure (App Service, Container Apps, VM…), the credential can be
**secretless** — verified in sample E5's [`appsettings.ManagedIdentity.json`](../../samples/MicrosoftGraph/appsettings.ManagedIdentity.json):

```jsonc
"Credentials": {
  "graph": {
    "Type": "TokenCredential",
    "Scope": "https://graph.microsoft.com/.default"
  }
}
```

No client secret, no token endpoint — `TokenCredential` takes the ambient Azure
identity. It declares only its own keys: CredProx refuses unknown keys per credential
type, so the two variants' credential blocks cannot be layered ([E5 README](../../samples/MicrosoftGraph/README.md)).

## Required secrets

| Secret | Holds |
|---|---|
| `graph-client-secret` | the app registration's client secret (client-credentials variant only — the managed-identity variant needs no secret) |

## Scopes and audiences

- `https://graph.microsoft.com/.default` requests the app's **configured** permissions
  (verified in sample E5); fine-grained scopes instead are a permission-model choice —
  see the admin-consent note in the table above and plan §8.6's parked Graph
  admin-consent variants.

## Gotchas

- **Two hosts, one config:** the token endpoint is `login.microsoftonline.com/<tenant-id>`
  while the API host is `graph.microsoft.com` — both appear in the block (verified in
  sample E5, which needs "two host values" per its README).
- Sovereign clouds (US Gov, China…) use different login/API hosts — **UNVERIFIED:**
  confirm against vendor docs and change both.
- **Admin consent:** app permissions must be consented by an admin before tokens
  carry them; a missing consent surfaces as token/API refusals, not config errors.
- Secret rotation via Key Vault + reload is the M26-proven pattern
  ([report](../live-validation-report.md) P4).
