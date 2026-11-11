# ADP

| | |
|---|---|
| **Auth model** | OAuth 2.0 client credentials at the ADP gateway, **plus mTLS on both the token call and the API calls** (verified in sample [E6](../../samples/ADP/README.md)) |
| **CredProx credential** | `OAuthClientCredentials` + a `Connections` mTLS entry |
| **Sample** | [E6 `samples/ADP`](../../samples/ADP/README.md) — WireMock stub smoke; the real-vendor variant is [`appsettings.RealAdp.json`](../../samples/ADP/appsettings.RealAdp.json) |
| **Verification** | The two-sided mTLS shape, the PFX-from-config/Key Vault handling and the certificate enforcement are verified offline in sample E6 (nginx-enforced). The endpoints follow the known-working integration (token on `accounts.adp.com`, API on `api.adp.com`); ADP's developer portal could not be reached from this build environment (2026-11-05), so acceptance of the request body CredProx sends, per-API scope syntax and token lifetimes are marked below. |

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
        "ClientCertificate": "secret:adpClientCert"
      }
    },
    "Credentials": {
      "adp": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "https://accounts.adp.com/auth/oauth/v2/token?grant_type=client_credentials",
        "ClientId": "<your-adp-client-id>",
        "ClientSecret": "secret:adpClientSecret",
        "TokenTypeName": "Bearer",
        "Connection": "adp-mtls"
      }
    },
    "Secrets": {
      "adpClientSecret": "",
      "adpClientCert": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "adp": {
        "ClusterId": "adp",
        "Methods": ["GET"],
        "Match": { "Path": "/adp/{**catch-all}" },
        "Transforms": [{ "PathRemovePrefix": "/adp" }],
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
| `adpClientSecret` | the OAuth client secret ADP issued with your client id |
| `adpClientCert` | the mTLS client certificate: **base64 passwordless PKCS#12 (PFX)** — the shape a Key Vault certificate's backing secret holds, so the vault value drops in unchanged. A PEM bundle (cert + key) is auto-detected too; see [E3 `samples/MutualTls`](../../samples/MutualTls/README.md). If the PFX is password-protected, add `ClientCertificatePassword`. |

## Scopes and audiences

- No `Scope` is sent by default — the known-working integration sent none. Add
  `"Scope": "..."` only if your ADP tenant asks for one (sent verbatim).
  **UNVERIFIED:** the real per-API scope strings — confirm against ADP's portal docs
  for the APIs you consume.

## Gotchas

- **mTLS is on both hops.** The credential's `Connection` covers the token call; the
  cluster metadata `CredProx.Connection` covers the API calls. Wiring only one of the
  two produces a token that works while every API call fails the TLS handshake
  (verified in sample E6 — the real variant sets both).
- **Token request shape.** The configured URL is sent verbatim, so the
  `?grant_type=client_credentials` query travels; CredProx additionally sends the
  RFC 6749 form body `grant_type=client_credentials` (measured in E6's wire check —
  the curated `samples/ADP/wire-check.txt`, re-asserted by the sample's smoke against a
  fresh recording each run). The known-working original sent the query with an empty body;
  **UNVERIFIED:** ADP's acceptance of the duplicate parameter — first real-vendor
  smoke should watch for it.
- **Token lifetime:** **UNVERIFIED**, confirm against vendor docs. CredProx caches per
  credential, refreshes early, and retries once on a vendor 401 (refresh-on-401), so a
  wrong lifetime assumption degrades gracefully rather than hard-failing.
