# Workday

| | |
|---|---|
| **Auth model** | Per-tenant OAuth 2.0 for integration clients. A Workday API client is configured with a client grant type of **JWT Bearer Grant** (recommended; an X.509 public key is registered on the client) or **Authorization Code + PKCE** — client_credentials is **not offered** (cited: doc.workday.com, "Register API Client" pages; design-architect's docs check 2026-11-05 — the portal is not reachable from this build environment). The CredProx path is `JwtAssertion` in RFC 7523 jwt-bearer-grant mode. |
| **CredProx credential** | `JwtAssertion` + `Exchange: JwtBearerGrant` — the library signs a JWT assertion and posts `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` + `assertion` to the token endpoint |
| **Sample** | None — closest verified mechanics: [E8 `samples/GitHubApp`](../../samples/GitHubApp/README.md) (same `JwtAssertion` config shape, different exchange) |
| **Verification** | The config block is CredProx-valid (CI binds and validates it through the real startup path); the grant-type facts are cited; the token-endpoint path, expected `Audience` value, scope strings and token lifetimes remain `UNVERIFIED`. |

## CredProx config

Fill the placeholders from your Workday **API client registration** ("Register API
Client") — the block is complete CredProx config once the `<...>` values are real.

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "workday": { "Template": "https://<workday-api-host>" }
    },
    "Credentials": {
      "workday": {
        "Type": "JwtAssertion",
        "Algorithm": "RS256",
        "SigningKey": "secret:workday-signing-key",
        "Issuer": "<api-client-id>",
        "Subject": "<integration-system-user>",
        "Audience": "https://<workday-token-endpoint>",
        "Exchange": "JwtBearerGrant",
        "TokenEndpoint": "https://<workday-token-endpoint>"
      }
    },
    "Secrets": {
      "workday-signing-key": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "workday": {
        "ClusterId": "workday",
        "Match": { "Path": "/workday/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/workday" } ],
        "Metadata": {
          "CredProx.Destination": "workday",
          "CredProx.Credential": "workday"
        }
      }
    },
    "Clusters": {
      "workday": {
        "Destinations": {
          "workday": { "Address": "https://<workday-api-host>/" }
        }
      }
    }
  }
}
```

`Issuer` is the API Client ID; the assertion is signed with `SigningKey`. No
`ClientSecret` is configured — Workday API clients authenticate with the registered
public key, not a client secret (cited: doc.workday.com, "Register API Client").
The assertion must carry a `sub` claim (cited: RFC 7523 §3, fetched 2026-11-05:
<https://datatracker.ietf.org/doc/html/rfc7523>) — set `Subject` to the Integration
System User selected on the API client; the exact value format is **UNVERIFIED**,
confirm it for your tenant.

## Required secrets

| Secret | Holds |
|---|---|
| `workday-signing-key` | the PKCS#8 PEM private key whose X.509 public key you registered on the Workday API client — it signs the JWT assertion |

## Scopes and audiences

- **UNVERIFIED:** scope strings and the expected `Audience` claim value. CredProx
  places `Audience` verbatim into the assertion; RFC 7523 expects the authorization
  server's token URL — confirm against vendor docs.

## Gotchas

- **Authorization Code + PKCE exists on Workday's side, but it is an interactive
  end-user flow; CredProx drives machine-to-machine integrations, so JWT Bearer
  Grant is the CredProx path here.**
- **The token exchange is bound to Integration System Users (ISUs):** the API
  client's registration selects which ISUs may receive tokens through the
  jwt-bearer grant (cited: doc.workday.com, "Register API Client") — pick the ISU
  whose security policy should govern the proxied calls.
- **Tenant hosts are deliberately unnamed here** (`<workday-api-host>`,
  `<workday-token-endpoint>`): Workday tenants live on tenant/pod-specific hosts and
  this page could not verify the pattern — copy them from your tenant's own API
  documentation, don't guess them into a shared config.
- Token caching/refresh work the same as for every CredProx credential (cache,
  early refresh, refresh-on-401). The assertion defaults to a 5-minute lifetime;
  Workday's maximum accepted assertion lifetime is **UNVERIFIED**.
