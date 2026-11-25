# Google APIs

| | |
|---|---|
| **Auth model** | Service-account OAuth 2.0: the application mints an **RS256 JWT assertion** whose required claims are `iss` (the service-account email), `scope` (space-delimited), `aud` (**always** `https://oauth2.googleapis.com/token` for a token request), `exp` (max 1 hour after `iat`) and `iat`, then POSTs `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` + `assertion` to that endpoint, which answers `access_token` / `token_type: Bearer` / `expires_in: 3600`. Vendor docs: [service account docs](https://developers.google.com/identity/protocols/oauth2/service-account) (fetched 2026-11-24) |
| **CredProx credential** | `JwtAssertion` + `Exchange: JwtBearerGrant` + **`ScopeInAssertion: true`**. The built-in mints the required claim set — `iss`, `scope`, `aud`, `exp`, `iat` (`jti` is minted beyond the required set and the cited page is silent about it, so Google's tolerance of that extra claim is UNVERIFIED here — offline milestone, no live run; `sub` appears only when domain-wide delegation sets `Subject`) — and its token POST carries only `grant_type` + `assertion`, matching Google's documented shape (cited above). The exchanged `access_token`/`expires_in` is cached and refreshed by the built-in |
| **Sample** | [`samples/GitHubApp`](../../samples/GitHubApp/README.md) for the `JwtAssertion` mechanics end-to-end; [`samples/CustomPlugin`](../../samples/CustomPlugin/README.md) only for the no-exchange direct-JWT variant named in the last gotcha |
| **Verification** | The config block below is bound in CI through the real fail-closed startup path, and the scope-in-claim placement is pinned offline against a Google-shaped token endpoint that answers `invalid_grant` to a scope-as-form-field request (`tests/CredProx.Tests`: `JwtAssertionProviderTests` and `VendorSnippetValidationTests`) — this proves the config and the claim placement, not live acceptance by Google; the claim set, token endpoint, response shape, delegation timing and the no-OAuth variant are cited from the Google page above (fetched 2026-11-24) |

## CredProx config

The working shape — correct grant, endpoint, audience and issuer, with `scope` minted
inside the signed claim set:

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "google": { "Template": "https://sheets.googleapis.com" }
    },
    "Credentials": {
      "google": {
        "Type": "JwtAssertion",
        "Algorithm": "RS256",
        "SigningKey": "secret:google-signing-key",
        "Issuer": "<service-account-email>",
        "Audience": "https://oauth2.googleapis.com/token",
        "Scope": "<space-delimited-google-scopes>",
        "ScopeInAssertion": true,
        "Exchange": "JwtBearerGrant",
        "TokenEndpoint": "https://oauth2.googleapis.com/token"
      }
    },
    "Secrets": {
      "google-signing-key": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "google": {
        "ClusterId": "google",
        "Match": { "Path": "/google/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/google" } ],
        "Metadata": {
          "CredProx.Destination": "google",
          "CredProx.Credential": "google"
        }
      }
    },
    "Clusters": {
      "google": {
        "Destinations": {
          "google": { "Address": "https://sheets.googleapis.com/" }
        }
      }
    }
  }
}
```

## Required secrets

| Secret | Holds |
|---|---|
| `google-signing-key` | the service-account JSON key file's **`private_key`** (PEM) — it signs the RS256 assertion |

The JSON file's `client_email` is the `Issuer` value above; it is an identifier, not a
secret.

## Scopes and audiences

- `scope` is a **space-delimited list of the permissions the application requests**, and
  for a token request `aud` is **always** `https://oauth2.googleapis.com/token` (cited:
  [service account docs](https://developers.google.com/identity/protocols/oauth2/service-account),
  fetched 2026-11-24). Google scopes are full URLs (the docs' example is
  `https://www.googleapis.com/auth/devstorage.read_only`), not short names.
- Domain-wide delegation adds `sub`: "include the email address of the user in the JWT
  claim set as the value of the `sub` field", and only after "permission to perform this
  type of impersonation must be granted" by a super administrator (cited: same page,
  fetched 2026-11-24). In CredProx that is `Subject`: the `sub` claim is minted only
  when it is configured, so leave it unset for plain service-account calls.
- `ScopeInAssertion: true` is what puts `Scope` in the claim set; with the option off
  (the default) the assertion carries no scope claim and the scope goes to the form
  instead — one supplier, never both.

## Gotchas

- **`scope` must be a JWT claim, so `ScopeInAssertion: true` is not optional here.**
  Google's required claim set is `iss`/`scope`/`aud`/`exp`/`iat` (cited: the service
  account page above, fetched 2026-11-24). With `ScopeInAssertion` on, the built-in
  mints `Scope` as the `scope` claim inside the signed assertion and drops the scope
  form parameter — the token POST then carries only `grant_type` and `assertion`, which
  is exactly the documented request (cited above). With it off — the default, and right
  for every other vendor — the assertion carries no scope claim and Google's endpoint
  rejects the request; startup also refuses the option on with no `Scope`. Offline CI
  pins both placements, including a Google-shaped stand-in that answers `invalid_grant`
  to scope-as-form-field. How Google's live endpoint answers in detail is **UNVERIFIED**
  here (offline milestone, no live run).
- **Assertion lifetime is capped at 1 hour by Google** (`exp` "has a maximum of 1 hour
  after the issued time"; cited: same page, fetched 2026-11-24). CredProx's built-in
  default assertion lifetime (5 minutes) sits well inside it; raising it buys nothing.
- **The API host is not the audience.** `aud` is the token endpoint above; each Google
  API answers on its own host (`https://sheets.googleapis.com/`,
  `https://firestore.googleapis.com/`, … — examples cited from the page above), so each
  API is its own `Destinations` entry/cluster while sharing one credential.
- **Delegation grants propagate slowly on purpose.** "It usually takes a few minutes for
  impersonation access to be granted after the client ID was added, but in some cases it
  might take up to 24 hours" (cited: same page, fetched 2026-11-24). A `sub` that 401s
  right after the admin grant is expected; it is not a CredProx cache fault.
- **Some Google APIs skip the exchange entirely.** For APIs with a service definition in
  the `googleapis` repo, Google documents using the signed JWT **directly as the bearer
  token** (cited: the addendum on the page above, fetched 2026-11-24). That shape — the
  assertion *is* the credential — is likewise not one of the built-in exchange modes, so
  it too lives behind the same plugin seam. The exchanged access token is reusable
  through its `expires_in: 3600` window (cited: response handling above), which the
  built-in credential caches and refreshes on 401 anyway.
