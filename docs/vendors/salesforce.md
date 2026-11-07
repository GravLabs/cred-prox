# Salesforce

| | |
|---|---|
| **Auth model** | OAuth 2.0 through a Connected App / External Client App. The org's authorization-server metadata is published at `/.well-known/oauth-authorization-server`; on the generic login host it serves `token_endpoint = https://login.salesforce.com/services/oauth2/token` with `issuer = https://login.salesforce.com` (that JSON, fetched 2026-11-05) |
| **CredProx credential** | `OAuthClientCredentials` with **`ClientAuthentication: FormPost`** (verified in sample [E15](../../samples/AgentEgress/README.md)) |
| **Sample** | [E15 `samples/AgentEgress`](../../samples/AgentEgress/README.md) — the Salesforce shape as pure config against an in-process stub |
| **Verification** | The well-known metadata (token endpoint, issuer) is cited from Salesforce itself. That discovery document lists only `authorization_code` and `refresh_token` grants — enabling the client-credentials (or JWT bearer) flow on your Connected App is **[UNVERIFIED: confirm against vendor docs]**, as is the per-org My Domain host you must actually call. |

## CredProx config

The block below is complete for a client-credentials connected app. Point
`TokenEndpoint` at **your org's** well-known metadata's `token_endpoint` (production,
sandbox, or My Domain) — check the live JSON rather than assuming.

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "salesforce": { "Template": "https://<your-org>.my.salesforce.com" }
    },
    "Credentials": {
      "salesforce": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "https://login.salesforce.com/services/oauth2/token",
        "ClientAuthentication": "FormPost",
        "ClientId": "<connected-app-consumer-key>",
        "ClientSecret": "secret:salesforce-client-secret",
        "Scope": "<api-scopes>"
      }
    },
    "Secrets": {
      "salesforce-client-secret": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "salesforce": {
        "ClusterId": "salesforce",
        "Match": { "Path": "/salesforce/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/salesforce" } ],
        "Metadata": {
          "CredProx.Destination": "salesforce",
          "CredProx.Credential": "salesforce"
        }
      }
    },
    "Clusters": {
      "salesforce": {
        "Destinations": {
          "salesforce": { "Address": "https://<your-org>.my.salesforce.com/" }
        }
      }
    }
  }
}
```

## Required secrets

| Secret | Holds |
|---|---|
| `salesforce-client-secret` | the Connected App's **consumer secret** (pairs with the consumer key in `ClientId`) |

## Scopes and audiences

- E15's stub models the shape with `Scope: api` (verified in sample E15 as a shape,
  not as a Salesforce fact). **UNVERIFIED:** the scopes your org needs — confirm
  against vendor docs and the Connected App's enabled OAuth scopes.

## Gotchas

- **`FormPost`, not a Basic header.** E15 drives Salesforce's client-credentials call
  with the credentials in the POST body — that is the shape the sample verifies
  against the stub. **UNVERIFIED:** confirm against vendor docs before switching it.
- **The login host is per-org.** My Domain orgs serve their own
  `/.well-known/oauth-authorization-server`; read the `token_endpoint` from your org
  instead of copying `login.salesforce.com`, and keep `Destinations`/cluster hosts on
  the matching org host so the token and the API agree.
- **Token lifetime and the returned `instance_url`:** **UNVERIFIED**, confirm against
  vendor docs. CredProx caches the token and refreshes on 401 regardless.
