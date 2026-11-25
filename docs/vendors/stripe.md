# Stripe

| | |
|---|---|
| **Auth model** | The API key **is** the credential. Stripe's API authenticates with HTTP Basic, API key as username and no password; bearer auth is also accepted (`Authorization: Bearer <key>`, the form Stripe shows for cross-origin requests). Keys are mode-prefixed: `sk_test_` (sandbox), `sk_live_` (all live resources), `rk_live_` (restricted). Vendor docs: [API authentication](https://docs.stripe.com/api/authentication), [keys](https://docs.stripe.com/keys) (fetched 2026-11-24) |
| **CredProx credential** | `StaticKey` — `Location: Header`, `Name: Authorization`, `Prefix: "Bearer "`; the Basic form works too with pre-encoded material (see below) |
| **Sample** | [`samples/AiGateway`](../../samples/AiGateway/README.md) for the `StaticKey` mechanics; Stripe itself has no sample here |
| **Verification** | The config block is CredProx-valid (CI binds it through the real startup path); the header shapes, key taxonomy, reveal/rotation behavior and version-defaults are cited from the Stripe pages listed per gotcha (fetched 2026-11-24) |

CredProx holds the key and strips the caller's own bearer first, so applications behind
the proxy can be given a caller identity without ever holding a Stripe key.

## CredProx config

The block pins the API version per request — Stripe otherwise answers every call with
the account's **default** version, which is upgradable in the Dashboard without any
change on your side (cited: [versioning](https://docs.stripe.com/api/versioning),
fetched 2026-11-24). Put the version your integration was built against (or today's
account default) in place of the placeholder.

```json credprox-snippet
{
  "CredProx": {
    "Destinations": {
      "stripe": { "Template": "https://api.stripe.com" }
    },
    "Credentials": {
      "stripe": {
        "Type": "StaticKey",
        "Location": "Header",
        "Name": "Authorization",
        "Prefix": "Bearer ",
        "Secret": "secret:stripe-secret-key"
      }
    },
    "Secrets": {
      "stripe-secret-key": ""
    }
  },
  "ReverseProxy": {
    "Routes": {
      "stripe": {
        "ClusterId": "stripe",
        "Match": { "Path": "/stripe/{**catch-all}" },
        "Transforms": [
          { "PathRemovePrefix": "/stripe" },
          { "RequestHeader": "Stripe-Version", "Set": "<api-version>" }
        ],
        "Metadata": {
          "CredProx.Destination": "stripe",
          "CredProx.Credential": "stripe"
        }
      }
    },
    "Clusters": {
      "stripe": {
        "Destinations": {
          "stripe": { "Address": "https://api.stripe.com/" }
        }
      }
    }
  }
}
```

If you prefer Stripe's headline **Basic** shape, keep the same route and change only the
credential: `Prefix: "Basic "` and store the username-encoded value — `key:` in base64,
empty password (username and encoding rule cited: the authentication page above):

```bash
printf '%s:' "$STRIPE_SECRET_KEY" | base64 -w0
```

## Required secrets

| Secret | Holds |
|---|---|
| `stripe-secret-key` | the `sk_test_…` / `sk_live_…` secret key, or better a `rk_live_…` **restricted** key; for the Basic form, its `key:`-in-base64 encoding instead |

## Scopes and audiences

- No OAuth: the blast radius of a standard secret key is **every API resource**.
  Stripe recommends restricted keys instead — "To protect your business, use restricted
  API keys" — each carrying an explicit permission subset (cited:
  [authentication](https://docs.stripe.com/api/authentication), fetched 2026-11-24).
- Keys can additionally carry **access policies** that limit which servers may use
  them; an out-of-policy request is blocked and the account is notified (cited:
  [keys](https://docs.stripe.com/keys), fetched 2026-11-24).

## Gotchas

- **A live secret key is shown once and cannot be recovered.** "Copy the key before you
  save it because you can't reveal it later… If you lose a key, rotate or delete it and
  create another" (cited: [keys](https://docs.stripe.com/keys), fetched 2026-11-24) —
  capture it into the secret source at creation time.
- **Rotation keeps both keys alive for up to 7 days.** A Dashboard roll leaves old and
  new working "for up to 7 days"; Stripe advises watching the old key's request volume
  and expiring it only after it reaches zero (cited: same page). That grace window is
  the moment to update CredProx's secret store and let the reload pick it up; nothing
  forces an immediate cutover.
- **The API version is a Dashboard-side default.** Every request uses the account's
  default version "unless you override it by setting the `Stripe-Version` header"
  (cited: [versioning](https://docs.stripe.com/api/versioning), fetched 2026-11-24).
  Set it on the route (shown above; the same `RequestHeader`/`Set` transform the
  `samples/AgentTokens` model route uses) so an account upgrade cannot silently change
  the contract every caller behind the proxy sees.
- **Test mode is a different key prefix, not a different host.** `sk_test_…` and
  `sk_live_…` both hit `https://api.stripe.com` (cited: the authentication page above) —
  separate credentials *and separate routes* per mode, so a sandbox caller can never
  spend live money through one shared route.
- **Publishable keys (`pk_…`) are not a CredProx credential.** They are safe to embed in
  clients (cited: same page); only the secret/restricted key belongs in `Secrets`.
