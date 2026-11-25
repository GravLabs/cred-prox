# Atlassian (Jira / Confluence)

| | |
|---|---|
| **Auth model** | HTTP **Basic** with an Atlassian-account **API token**: build `useremail:api_token`, BASE64 encode it, send it as the Basic credential. Accounts with two-step verification must authenticate scripts with an API token, not a password. Vendor docs: [basic auth for Jira REST](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/), [manage API tokens](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/) (fetched 2026-11-24) |
| **CredProx credential** | `StaticKey` — `Location: Header`, `Name: Authorization`, `Prefix: "Basic "`, with the **pre-encoded** `email:token` pair as the secret. The existing credential types **can** express the Basic header; no plugin route is needed |
| **Sample** | [`samples/AiGateway`](../../samples/AiGateway/README.md) for the `StaticKey` mechanics; Atlassian itself has no sample here |
| **Verification** | The config block is CredProx-valid (CI binds it through the real startup path); the Basic construction, token reveal/expiry/revocation rules, scope model and the OAuth recommendation are cited from the Atlassian pages listed per gotcha (fetched 2026-11-24) |

CredProx attaches `Authorization: Basic <pre-encoded email:token>` to every proxied call
and strips the caller's own bearer first. **CredProx does not base64-encode anything** —
Atlassian's encoding step happens when you create the secret material:

```bash
printf '%s' "you@example.com:API_TOKEN" | base64 -w0
```

## CredProx config

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "atlassian": { "Template": "https://<your-site>.atlassian.net" }
    },
    "Credentials": {
      "atlassian": {
        "Type": "StaticKey",
        "Location": "Header",
        "Name": "Authorization",
        "Prefix": "Basic ",
        "Secret": "secret:atlassian-basic-pair"
      }
    },
    "Secrets": {
      "atlassian-basic-pair": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "atlassian": {
        "ClusterId": "atlassian",
        "Match": { "Path": "/atlassian/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/atlassian" } ],
        "Metadata": {
          "CredProx.Destination": "atlassian",
          "CredProx.Credential": "atlassian"
        }
      }
    },
    "Clusters": {
      "atlassian": {
        "Destinations": {
          "atlassian": { "Address": "https://<your-site>.atlassian.net/" }
        }
      }
    }
  }
}
```

## Required secrets

| Secret | Holds |
|---|---|
| `atlassian-basic-pair` | the BASE64 of `email:api_token` (the construction above) — **not** the raw token; CredProx writes `Basic ` + this value verbatim |

## Scopes and audiences

- No audience. Plain API tokens carry the account's full access; **tokens created with
  scopes** name the app (Jira or Confluence) and the scopes at creation ("Select the
  scopes to determine what the API token can do in Jira or Confluence", cited: [manage
  API tokens](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/),
  fetched 2026-11-24). Scoped tokens address the gateway
  `https://api.atlassian.com/ex/<product>/{cloudId}` instead of the site host — that is
  a second destination, same credential mechanics.

## Gotchas

- **The Basic credential must arrive pre-encoded.** Atlassian's own recipe is build
  `useremail:api_token` then BASE64 it (their example: `echo -n
  "user@example.com:api_token_string" | base64`; cited: [basic auth for Jira
  REST](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/),
  fetched 2026-11-24). `StaticKey`'s `Prefix` composes the header but performs no
  encoding; store the encoded pair and keep the encoding step in your secret-minting
  runbook.
- **The token is shown once and cannot be recovered.** "You can't recover the API token
  after you're done with this step" (cited: [manage API
  tokens](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/),
  fetched 2026-11-24) — encode and save it into the secret source at creation time.
- **Tokens expire.** Default lifetime is now one year (since 2024-12-15, settable to
  1–365 days at creation), and Atlassian force-expired tokens created before that date
  during 2026-03-14…2026-05-12 (cited: same page, fetched 2026-11-24). Calendar the
  rotation, mint the replacement pair before the deadline, and let CredProx's secret
  reload swap it.
- **The credential is a person.** The token belongs to an Atlassian account (that email
  is the Basic username), so every proxied call acts as that user, and revocation at
  `id.atlassian.com` or the account's removal kills the route's access. Use a dedicated
  integration account (cited: same page — tokens are generated from "your Atlassian
  account", and revocation is per token there, fetched 2026-11-24).
- **Atlassian nudges past Basic for apps.** OAuth 2.0 (3LO) and the app frameworks'
  auth are described as more secure than basic auth (cited: [basic auth for Jira
  REST](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/),
  fetched 2026-11-24). Basic-with-API-token remains the documented path for scripts and
  server-to-server REST calls — that is exactly the shape a proxy holds.
