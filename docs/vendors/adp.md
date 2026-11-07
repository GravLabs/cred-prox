# ADP

| | |
|---|---|
| **Auth model** | OAuth 2.0 client credentials at the ADP gateway, **plus mTLS on both the token call and the API calls** (verified in sample [E6](../../samples/ADP/README.md)) |
| **CredProx credential** | `OAuthClientCredentials` + a `Connections` mTLS entry |
| **Sample** | [E6 `samples/ADP`](../../samples/ADP/README.md) — WireMock stub smoke; the real-vendor variant is [`appsettings.RealAdp.json`](../../samples/ADP/appsettings.RealAdp.json) |
| **Verification** | Endpoints and the two-sided mTLS shape are verified in sample E6 (real variant). ADP's developer portal could not be reached from this build environment (2026-11-05), so per-API scope syntax and token lifetimes are marked below. |

## CredProx config

One complete block — routes, cluster, credential, destination and the secrets it
references. Replace the `<placeholders>` and supply the secrets through any secret
source (environment, file, Key Vault); `CredProx:Secrets` here is the inline source.

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "adp": { "Template": "https://api.adp.com" }
    },
    "Connections": {
      // mTLS client certificate for the token call (credential Connection)
      // and the API calls (cluster metadata CredProx.Connection).
      "adp-mtls": {
        "ClientCertificate": "secret:adp-client-cert"
      }
    },
    "Credentials": {
      "adp": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "https://api.adp.com/oauth2/token",
        "ClientId": "<your-adp-client-id>",
        "ClientSecret": "secret:adp-client-secret",
        "Scope": "<api-scopes>",
        "TokenTypeName": "Bearer",
        "Connection": "adp-mtls"
      }
    },
    "Secrets": {
      "adp-client-secret": "",
      "adp-client-cert": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "adp": {
        "ClusterId": "adp",
        "Match": { "Path": "/adp/{**catch-all}" },
        "Metadata": {
          "CredProx.Destination": "adp",
          "CredProx.Credential": "adp"
        }
      }
    },
    "Clusters": {
      "adp": {
        "Destinations": {
          "adp": { "Address": "https://api.adp.com/" }
        },
        "Metadata": { "CredProx.Connection": "adp-mtls" }
      }
    }
  }
}
```

## Required secrets

| Secret | Holds |
|---|---|
| `adp-client-secret` | the OAuth client secret ADP issued with your client id |
| `adp-client-cert` | the mTLS client certificate bundle (cert PEM + private key PEM; same value shape as [E3 `samples/MutualTls`](../../samples/MutualTls/README.md) uses for `CredProx:Connections`) |

## Scopes and audiences

- `Scope` is sent verbatim on the token request. The stub in E6 uses `workforce`;
  **UNVERIFIED:** the real per-API scope strings — confirm against ADP's portal docs
  for the APIs you consume.

## Gotchas

- **mTLS is on both hops.** The credential's `Connection` covers the token call; the
  cluster metadata `CredProx.Connection` covers the API calls. Wiring only one of the
  two produces a token that works while every API call fails the TLS handshake
  (verified in sample E6 — the real variant sets both).
- **Token lifetime:** **UNVERIFIED**, confirm against vendor docs. CredProx caches per
  credential, refreshes early, and retries once on a vendor 401 (refresh-on-401), so a
  wrong lifetime assumption degrades gracefully rather than hard-failing.
