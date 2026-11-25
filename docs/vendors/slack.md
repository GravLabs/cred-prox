# Slack

| | |
|---|---|
| **Auth model** | OAuth tokens obtained when the app is installed into a workspace; the machine-to-machine path is a **bot token** (`xoxb-…`) sent as `Authorization: Bearer <token>`. Vendor docs: [tokens](https://docs.slack.dev/authentication/tokens), [Web API calling convention](https://docs.slack.dev/apis/web-api/) (fetched 2026-11-24) |
| **CredProx credential** | `StaticKey` — `Location: Header`, `Name: Authorization`, `Prefix: "Bearer "` (same shape as [OpenAI](openai.md) and the [`samples/AiGateway`](../../samples/AiGateway/README.md) provider key) |
| **Sample** | [`samples/AiGateway`](../../samples/AiGateway/README.md) for the `StaticKey` bearer mechanics; Slack itself has no sample here |
| **Verification** | The config block is CredProx-valid (CI binds it through the real startup path); the bearer shape, token identity model, scope model, rate-limit behavior and token-lifecycle facts are cited from the Slack pages listed per gotcha (fetched 2026-11-24) |

CredProx holds the bot token, attaches it to every proxied Slack call and strips the
caller's own bearer first — a Slack bot token authenticates the **app**, so callers
need never see it.

## CredProx config

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "slack": { "Template": "https://slack.com" }
    },
    "Credentials": {
      "slack": {
        "Type": "StaticKey",
        "Location": "Header",
        "Name": "Authorization",
        "Prefix": "Bearer ",
        "Secret": "secret:slack-bot-token"
      }
    },
    "Secrets": {
      "slack-bot-token": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "slack": {
        "ClusterId": "slack",
        "Match": { "Path": "/slack/{**catch-all}" },
        "Transforms": [ { "PathRemovePrefix": "/slack" } ],
        "Metadata": {
          "CredProx.Destination": "slack",
          "CredProx.Credential": "slack"
        }
      }
    },
    "Clusters": {
      "slack": {
        "Destinations": {
          "slack": { "Address": "https://slack.com/" }
        }
      }
    }
  }
}
```

## Required secrets

| Secret | Holds |
|---|---|
| `slack-bot-token` | the app's **bot token**, `xoxb-…`, from the OAuth install (or the app management console for internal apps) |

## Scopes and audiences

- There is no audience parameter. The token's power is its **scopes**, granted per
  workspace when the app is installed; Slack recommends newer **granular** bot scopes
  over the legacy umbrella `bot` scope (cited: [tokens](https://docs.slack.dev/authentication/tokens),
  fetched 2026-11-24). Slack's own Web API example posts `chat.postMessage` with a
  token that holds `channels:read` (cited: the [Web API
  page](https://docs.slack.dev/apis/web-api/), fetched 2026-11-24).

## Gotchas

- **The Web API lives on `slack.com`, not `api.slack.com`.** Every official call
  example uses `https://slack.com/api/<method>` (cited: the Web API page above) — point
  the destination template and cluster at `https://slack.com`.
- **A bot token is the app's identity, not a user's.** It "isn't tied to a user's
  identity" and the app "can stay installed even when an installing user is
  deactivated" (cited: [tokens](https://docs.slack.dev/authentication/tokens), fetched
  2026-11-24) — good news for a shared proxy credential; acting *as* a user needs a
  user token (`xoxp-…`), which is a different credential per user.
- **Throttling is per method, per workspace, per minute.** Every Web API method carries
  a tier (1–4), the window is a minute, and a limit refusal is `429` with a
  `Retry-After` seconds header; "calls to other methods on behalf of this workspace are
  not restricted" (cited: [rate
  limits](https://docs.slack.dev/apis/web-api/rate-limits/), fetched 2026-11-24). Honor
  `Retry-After` and size CredProx `Throttling` per route — a global limiter punishes
  unrelated methods for one chatty caller.
- **Legacy umbrella `bot` tokens are a dead end.** Newer platform features are no
  longer supported with them, non-`bot` scopes requested at install have no effect, and
  revoking one with `auth.revoke` does **not** uninstall the bot user (cited: the tokens
  page above). Mint granular tokens; treat token lifecycle as install/uninstall, not a
  rotate-in-place.
- **Never park a `xwfp-` workflow token in config.** Workflow tokens expire 15 minutes
  after issue (or at function-step completion, whichever comes first) and are revoked
  immediately (cited: the tokens page above). Only install-time bot/user tokens belong
  in `Secrets`.
