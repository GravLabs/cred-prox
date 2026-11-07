# GitHub Apps

| | |
|---|---|
| **Auth model** | Two-step: the app signs a short-lived **RS256 JWT** (claims `iss` = the App/client id, `iat`, `exp`; `exp` at most **10 minutes** into the future; PEM private key), presents it as a bearer to the installation endpoint, and receives an **installation access token** valid about **1 hour**. Vendor docs: [generating a JWT](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app), [exchanging for an installation token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) (fetched 2026-11-05) |
| **CredProx credential** | `JwtAssertion` in `BearerExchange` mode — the whole dance is config |
| **Sample** | [E8 `samples/GitHubApp`](../../samples/GitHubApp/README.md) — `-- --smoke` runs the flow in-process against stubs |
| **Verification** | CredProx mapping verified in sample E8; the JWT spec, exchange endpoint, headers and token lifetime are cited from the GitHub docs above |

CredProx does the whole exchange: it signs the JWT per its options, `POST`s it as
`Authorization: Bearer <jwt>` to the installation endpoint, reads `token` (and the
optional `expires_at`) from the response, caches the installation token, and attaches
it to every proxied call — refreshing on expiry and on a vendor 401.

## CredProx config

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "github": { "Template": "https://api.github.com" }
    },
    "Credentials": {
      "github-app": {
        "Type": "JwtAssertion",
        "Algorithm": "RS256",
        "SigningKey": "secret:github-app-signing-key",
        "Audience": "https://api.github.com",
        "Lifetime": "00:09:00",
        "Exchange": "BearerExchange",
        "TokenField": "token",
        "ExpiresAtField": "expires_at",
        "Issuer": "<your-github-app-id>",
        "TokenEndpoint": "https://api.github.com/app/installations/<installation-id>/access_tokens"
      }
    },
    "Secrets": {
      "github-app-signing-key": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "github": {
        "ClusterId": "github",
        "Match": { "Path": "/github/{**catch-all}" },
        "Transforms": [
          { "PathRemovePrefix": "/github" }
        ],
        "Metadata": {
          "CredProx.Destination": "github",
          "CredProx.Credential": "github-app"
        }
      }
    },
    "Clusters": {
      "github": {
        "Destinations": {
          "github": { "Address": "https://api.github.com/" }
        }
      }
    }
  }
}
```

## Required secrets

| Secret | Holds |
|---|---|
| `github-app-signing-key` | the App's RSA **private key in PEM form** — generated on the App settings page; GitHub keeps only the public half |

## Scopes and audiences

- The JWT's effective identity comes from `iss` (the App id); the vendor docs
  recommend the client id value. Audience in the options above is the API host; the
  per-installation grants — repositories and permissions — live on GitHub, not in
  this config: the installation token carries what the installation was granted.

## Gotchas

- **`Lifetime` must stay ≤ 10 minutes** — GitHub rejects a JWT whose `exp` is further
  out (the 9-minute value above leaves a minute of clock slack; verified against the
  docs citation and E8's sample value).
- **Don't pin the token format.** GitHub notes installation tokens can arrive in a new
  **stateless format**; code that assumes exactly 40 characters may break. CredProx
  treats the token as an opaque string (`TokenField`), so nothing here pins it — do
  the same in your own code.
- **Clock skew is a silent failure.** A wrong host clock puts `iat`/`exp` outside
  GitHub's window and every exchange 401s; refresh-on-401 will not help. NTP your host.
- One credential serves **one installation** (the installation id is in the token
  endpoint). For several installations, one credential each, and route per target.
