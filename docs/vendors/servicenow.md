# ServiceNow

| | |
|---|---|
| **Auth model** | Per-instance OAuth 2.0 provider. An **OAuth API client** (client-credentials grant) is registered in the instance's OAuth application registry; tokens are issued by that instance at `https://<instance>.service-now.com/oauth_token.do`. **Cited (2026-11-05):** the inbound client-credentials grant and that token-endpoint form are documented in the SailPoint ServiceNow connector docs (fetched 2026-11-05: <https://documentation.sailpoint.com/connectors/servicenow/identity_governance/help/integrating_snow_identity_governance_connector/oauth2.0_auth.html>) and ServiceNow's OAuth-Inbound docs (design-architect's docs check 2026-11-05: <https://www.servicenow.com/docs/r/hX5GtoLUEU58KgyL7CW5Ag/1E8_x~A4Gcv7fjPNqX8lKg>). Scope syntax and token lifetimes remain **UNVERIFIED**. |
| **CredProx credential** | `OAuthClientCredentials` (no sample) |
| **Sample** | None — the closest verified mechanics are [E2 `samples/OAuthKeycloak`](../../samples/OAuthKeycloak/README.md) (plain client credentials) and [E4](../../samples/Spotify/README.md)/[E5](../../samples/MicrosoftGraph/README.md) for header-vs-form client auth variants |
| **Verification** | The config block is CredProx-valid (CI binds and validates it through the real startup path); the grant type and token-endpoint form are cited; scope syntax and token lifetimes remain `UNVERIFIED`. |

## CredProx config

Fill the placeholders from your instance's OAuth API client — the block is complete
CredProx config once the `<...>` values are real.

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "servicenow": { "Template": "https://<instance>.service-now.com" }
    },
    "Credentials": {
      "servicenow": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "https://<instance>.service-now.com/oauth_token.do",
        "ClientAuthentication": "FormPost",
        "ClientId": "<oauth-api-client-id>",
        "ClientSecret": "secret:servicenow-client-secret",
        "Scope": "<required-scopes>"
      }
    },
    "Secrets": {
      "servicenow-client-secret": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "servicenow": {
        "ClusterId": "servicenow",
        "Match": { "Path": "/servicenow/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/servicenow" } ],
        "Metadata": {
          "CredProx.Destination": "servicenow",
          "CredProx.Credential": "servicenow"
        }
      }
    },
    "Clusters": {
      "servicenow": {
        "Destinations": {
          "servicenow": { "Address": "https://<instance>.service-now.com/" }
        }
      }
    }
  }
}
```

## Required secrets

| Secret | Holds |
|---|---|
| `servicenow-client-secret` | the client secret of the instance's OAuth API client |

## Scopes and audiences

- **UNVERIFIED:** scope strings (confirm against vendor docs — they come from the
  scopes/text-for-clients configured on the registry entry).

## Gotchas

- **All three places must agree on the same instance host** (destination template,
  cluster address, token endpoint). `<instance>.service-now.com` + `/oauth_token.do`
  is the cited standard form (URLs in the Auth model row); an instance on a custom
  domain substitutes its own host everywhere.
- **Client-credentials must be enabled on the instance:** the system property
  `glide.oauth.inbound.client.credential.grant_type.enabled` must exist with value
  `true`, or inbound token requests are refused (ServiceNow KB1645212; cited via
  design-architect's docs check, 2026-11-05).
- **The OAuth API client must have an integration user assigned**, or the token
  request fails with `unauthorized_client` (same citation as the property above).
- **Token expiry is instance-profile configuration** — **UNVERIFIED** default;
  CredProx reads the response's expiry, caches, refreshes early and on 401, so an
  instance with a short expiry needs no extra config here.
