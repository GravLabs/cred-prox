# Spotify

| | |
|---|---|
| **Auth model** | OAuth 2.0 client credentials at `accounts.spotify.com`; the token is presented as a bearer to `api.spotify.com` (verified in sample [E4](../../samples/Spotify/README.md)) |
| **CredProx credential** | `OAuthClientCredentials` with `ClientAuthentication: BasicHeader` |
| **Sample** | [E4 `samples/Spotify`](../../samples/Spotify/README.md) — "a real public vendor in explicit config"; nightly smoke with a free Spotify app |
| **Verification** | All endpoints, the Basic client auth and the two-host shape are verified in sample E4 |

## CredProx config

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "spotify": { "Template": "https://api.spotify.com" }
    },
    "Credentials": {
      "spotify": {
        "Type": "OAuthClientCredentials",
        "TokenEndpoint": "https://accounts.spotify.com/api/token",
        "ClientId": "<your-spotify-client-id>",
        "ClientAuthentication": "BasicHeader",
        "ClientSecret": "secret:spotify-client-secret"
      }
    },
    "Secrets": {
      "spotify-client-secret": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "spotify": {
        "ClusterId": "spotify",
        "Match": { "Path": "/spotify/{**catch-all}" },
        "Transforms": [
          { "PathRemovePrefix": "/spotify" }
        ],
        "Metadata": {
          "CredProx.Destination": "spotify",
          "CredProx.Credential": "spotify"
        }
      }
    },
    "Clusters": {
      "spotify": {
        "Destinations": {
          "spotify": { "Address": "https://api.spotify.com/" }
        }
      }
    }
  }
}
```

## Required secrets

| Secret | Holds |
|---|---|
| `spotify-client-secret` | the Spotify app's client secret (pairs with `ClientId`) |

## Scopes and audiences

- Client-credentials tokens are app-level (no user scopes); individual Web API
  endpoints document their required scope. E4 needs no `Scope` value (verified in
  sample E4).

## Gotchas

- **Basic client auth:** Spotify expects `client_id:client_secret` as an HTTP **Basic**
  header on the token call — that is `ClientAuthentication: "BasicHeader"` above
  (verified in sample E4); the default form-post authentication belongs to other
  vendors (E15's Salesforce shape).
- **Two host values:** the token host (`accounts.spotify.com`) and the API host
  (`api.spotify.com`) are different — both appear in the block, per E4's README.
