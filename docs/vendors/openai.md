# OpenAI

| | |
|---|---|
| **Auth model** | HTTP **Bearer** with an API key (`Authorization: Bearer <key>`); the same header also accepts short-lived access tokens minted through workload identity federation. API keys live per organization/project. Vendor docs: [authentication](https://developers.openai.com/api/reference/overview#authentication) (fetched 2026-11-24) |
| **CredProx credential** | `StaticKey` — `Location: Header`, `Name: Authorization`, `Prefix: "Bearer "` (the same shape the [`samples/AiGateway`](../../samples/AiGateway/README.md) provider key uses) |
| **Sample** | [`samples/AiGateway`](../../samples/AiGateway/README.md) — caller keys in front, provider key held by CredProx only, against an offline stand-in |
| **Verification** | The config block is CredProx-valid (CI binds it through the real startup path); the bearer shape, org/project headers, revocation timing, throttle codes and rate-limit meters are cited from the OpenAI docs pages listed on each gotcha (fetched 2026-11-24) |

CredProx resolves `secret:openai-api-key` per call, attaches `Authorization: Bearer
<key>` to every proxied request, strips the caller's own bearer before forwarding, and
scrubs the provider key out of anything the upstream reflects back.

## CredProx config

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "openai": { "Template": "https://api.openai.com" }
    },
    "Credentials": {
      "openai": {
        "Type": "StaticKey",
        "Location": "Header",
        "Name": "Authorization",
        "Prefix": "Bearer ",
        "Secret": "secret:openai-api-key"
      }
    },
    "Secrets": {
      "openai-api-key": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "openai": {
        "ClusterId": "openai",
        "Match": { "Path": "/openai/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/openai" } ],
        "Metadata": {
          "CredProx.Destination": "openai",
          "CredProx.Credential": "openai"
        }
      }
    },
    "Clusters": {
      "openai": {
        "Destinations": {
          "openai": { "Address": "https://api.openai.com/" }
        }
      }
    }
  }
}
```

## Required secrets

| Secret | Holds |
|---|---|
| `openai-api-key` | the organization/project **API key**; OpenAI says to treat it as a secret never exposed in client-side code and to load it from an environment variable or a key-management service (cited: the authentication page above) |

## Scopes and audiences

- There are **no OAuth scopes or audiences** on this path. The key's blast radius comes
  from its organization/project and from **API key governance** restrictions admins set
  (service-account vs user-owned project keys; org-level restrictions take precedence
  and apply to new key creation only — cited: [production best
  practices](https://developers.openai.com/api/docs/guides/production-best-practices),
  fetched 2026-11-24).
- Legacy user API keys (and members of several organizations) additionally send
  `OpenAI-Organization: <org-id>` and `OpenAI-Project: <project-id>` headers to choose
  attribution; usage counts to whichever org/project the headers name (cited: the
  authentication page above). Project-scoped keys already carry the answer.

## Gotchas

- **Revocation is fast, other key changes are not.** A revoked key stops working "within
  a few seconds", but most other authentication-affecting updates propagate within
  **15 minutes, potentially longer** (cited: the authentication page above). After
  rotating a key expect a window where the old one still authenticates; pair rotation
  with CredProx's secret reload so both ends converge.
- **Do not retry every 429.** Quota and billing refusals carry
  `insufficient_quota` / `billing_hard_limit_reached`, and OpenAI's own retry examples
  stop on those codes while honouring `Retry-After` (seconds or an HTTP date) for
  throttled 429s (cited: [rate limits](https://developers.openai.com/api/docs/guides/rate-limits),
  fetched 2026-11-24). A retrying proxy in front of a hard limit just burns quota.
- **The limits are multi-meter.** RPM, RPD, TPM, TPD, IPM and audio-minutes-per-minute
  all apply and "rate limits can be hit across any of the options depending on what
  occurs first", with higher usage tiers (Build/Launch/Grow) raising them (cited: same
  page). CredProx's caller budgets count requests — a TPM-stalled caller still fits
  every request-count shape, so size `Throttling` against the meter your traffic
  actually fills.
- **Throttle codes moved.** Rapid traffic increases that once answered `503 slow_down`
  now answer **429 `slow_down`**, while model overload stays `503` with
  `server_is_overloaded` (cited: same page). Match on status **and** `error.code`, not
  on the status alone.
- **The bearer is the whole credential.** Nothing else identifies the caller upstream —
  keep the caller's own bearer stripped (CredProx's default header hygiene, per
  `docs/production.md`) so the upstream can never see a caller token next to the
  provider key (shape verified in sample AiGateway).
