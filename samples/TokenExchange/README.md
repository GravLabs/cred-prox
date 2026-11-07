# E14 — TokenExchange: the caller's user token, exchanged per user for a downstream token

## What it demonstrates

The `TokenExchange` credential type (plan §3.6) in `Rfc8693` mode against a **real
Keycloak**: a caller presents a user token minted for the proxy (`aud credprox-proxy`),
CredProx **validates it** (signature, issuer, audience, lifetime) through the realm JWKS,
exchanges it at the IdP for a token minted for the downstream (`aud credprox-downstream`),
caches it **per user**, and attaches only the exchanged token. The protected downstream
validates its own audience — so the caller's inbound token is refused by it: the swap is
provable, not assumed. The caller API key is still required: the caller answers *which
app*, the inbound token answers *which user*.

Four properties the smoke checks:

- **alice and bob each get their own downstream token** — the API echoes
  `preferred_username|azp`, and `azp=credprox-proxy` proves the downstream saw the
  *exchanged* token, never the inbound one (`azp=credprox-frontend`).
- **a forged inbound token dies at validation**: an attacker-crafted JWT claiming alice
  gets `401 credprox.inbound_token_invalid` — and the 401-vs-502 split proves the
  exchange endpoint was never called (an exchange failure is 502).
- **the caller key is still required** — a valid user token without it is 401.
- **the inbound token sent straight to the downstream is refused** — wrong audience.

## What you need

Docker (`docker compose up`). No accounts — Keycloak 26 runs locally with an imported
realm (standard token exchange is built in since 26.2). Users `alice`/`alice` and
`bob`/`bob`; every secret here is a throwaway demo value inside containers that exist
only for this example.

## Run it

```bash
cd samples/TokenExchange
docker compose up -d --build   # Keycloak (:5094), protected API (:5088), proxy (:5092)
```

Get a user token from Keycloak (direct grant — stands in for whatever your frontend does):

```bash
ALICE=$(curl -s -X POST \
  -d "grant_type=password" -d "client_id=credprox-frontend" \
  -d "username=alice" -d "password=alice" \
  http://localhost:5094/realms/credprox/protocol/openid-connect/token \
  | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
```

Through the proxy — caller key **and** the user token:

```bash
curl -s -H "X-CredProx-Key: e14a7c3f9b2d48015ae6c8b4d7f29e53" \
     -H "Authorization: Bearer $ALICE" http://localhost:5092/
```

```
alice|credprox-proxy
```

`alice` is the user from the validated inbound token; `credprox-proxy` is the
authorized party of the **exchanged** token. Bob gets his own:

```bash
BOB=$(curl -s -X POST -d "grant_type=password" -d "client_id=credprox-frontend" \
  -d "username=bob" -d "password=bob" \
  http://localhost:5094/realms/credprox/protocol/openid-connect/token \
  | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
curl -s -H "X-CredProx-Key: e14a7c3f9b2d48015ae6c8b4d7f29e53" \
     -H "Authorization: Bearer $BOB" http://localhost:5092/
```

```
bob|credprox-proxy
```

The inbound token is useless at the downstream directly — its audience is the proxy:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $ALICE" http://localhost:5088/
```

```
401
```

And a valid user token without the caller key never reaches the exchange:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $ALICE" http://localhost:5092/
```

```
401
```

## The exact config

```jsonc
"CredProx": {
  "Callers": {
    "app-a": { "Keys": [ { "KeyId": "app-a-key-1", "KeyHash": "sha256:9743f3dc…" } ] }
  },
  "Credentials": {
    "downstream": {
      "Type": "TokenExchange",
      "Mode": "Rfc8693",
      "Issuer": "http://keycloak:8080/realms/credprox",
      "JwksUri": "http://keycloak:8080/realms/credprox/protocol/openid-connect/certs",
      "Audience": "credprox-proxy",          // mandatory: inbound tokens must be minted for THIS proxy
      "TokenEndpoint": "http://keycloak:8080/realms/credprox/protocol/openid-connect/token",
      "ClientId": "credprox-proxy",
      "ClientSecret": "secret:keycloak-proxy-secret",
      "RequestedAudience": "credprox-downstream"
    }
  },
  "Secrets": { "keycloak-proxy-secret": "credprox-proxy-secret" },
  "Audit": { "Enabled": true }
}
```

The route carries `CredProx.Credential=downstream`. The cache key is
`(downstream, u:<sub>)` — one exchanged token per user, refreshed on 401 for exactly
that user's entry.

## Realm notes (the Keycloak side of the trust)

`realm/credprox-realm.json` carries three things a real deployment needs to think about:

- **`credprox-proxy` is a confidential client with `standard.token.exchange.enabled`** —
  Keycloak 26.2+ standard token exchange (RFC 8693) is built in; the exchanging client
  just needs the switch.
- **The inbound token must carry the requester in its audience** (Keycloak's rule, and
  good practice anyway): the frontend client's default scopes include an audience mapper
  adding `credprox-proxy`; the proxy client's include one adding `credprox-downstream` —
  exchanged tokens take the *requester's* scopes, and the `audience` request parameter
  only down-scopes them.
- **`KC_HOSTNAME=http://keycloak:8080`** pins one issuer for every route (the classic
  IdP-behind-a-proxy shape): tokens minted through the host port and exchanges called
  over the docker network agree on `iss`, which Keycloak checks on the `subject_token`.
  A full-model realm import does not create Keycloak's built-in client scopes, so the
  realm carries its own `subject` scope (the same `oidc-sub-mapper` the built-in `basic`
  scope uses) — without it the tokens have no `sub` and CredProx correctly refuses them
  (`missing-subject`).

## Verify it

```bash
cd samples/TokenExchange && ./smoke.sh
```

Checks alice and bob each get their own exchanged downstream token, a forged (HS256,
attacker-secret) inbound token gets `401 credprox.inbound_token_invalid` with no exchange
attempted, a keyless request gets 401, and the inbound token is refused by the downstream
audience check. Prints `SMOKE OK`.

## What just happened

Tracing `curl -H "X-CredProx-Key: …" -H "Authorization: Bearer $ALICE" http://localhost:5092/`:

1. Caller auth resolves the key to `app-a`; the route needs a credential, so the attach
   feature reads the `Bearer` inbound token onto the provider context (a credential
   without `IRequiresInboundToken` would never see it).
2. The provider validates the inbound token against the realm JWKS — signature, issuer,
   **audience** (`credprox-proxy`), lifetime. A rejection is `401
   credprox.inbound_token_invalid` naming only the kind; nothing reaches the IdP.
3. The validated `sub` keys the cache (`u:<sub>`): first request for alice exchanges,
   later ones reuse. The exchange POSTs `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
   with `subject_token`/`subject_token_type`/`audience` and Basic client auth.
4. The exchanged token (`aud credprox-downstream`, `azp=credprox-proxy`) replaces
   `Authorization` — the inbound token never leaves the proxy — and the downstream
   validates its own audience and echoes `alice|credprox-proxy`.
5. On a downstream 401, the refresh handler invalidates exactly alice's cache entry
   (the provider recorded `CachePartition`), not everyone's.
