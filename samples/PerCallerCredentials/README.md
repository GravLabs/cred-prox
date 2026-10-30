# E7 — PerCallerCredentials: one route, one credential, one vendor account per caller

## What it demonstrates

Three inbound callers share **one route and one credential definition**, yet each is served
by a **different Keycloak account**: the credential is partitioned `caller:`, and its
`ClientId`/`ClientSecret` templates expand `{partition}` to the authenticated caller name.
A fourth thing happens for free: `app-readonly` carries an operation allow-list, so its GETs
pass and its POST is blocked with 403 before anything is forwarded. Every call — proxied or
rejected — lands in the audit sink with the caller identity, the credential NAME (never a
value), status, latency and bytes.

## What you need

Docker (`docker compose up`). No accounts — Keycloak runs locally with an imported realm.
The caller keys and client secrets here are throwaway demo values inside containers that
exist only for this example.

## Run it

```bash
cd samples/PerCallerCredentials
docker compose up -d --build   # Keycloak (:5093), protected API (:5084), proxy (:5083)
```

The demo caller keys (high-entropy random values; see the note below):

```bash
KEY_A=9f3a7c2e5b8d1460ae7c4f2b9d8e1a63
KEY_B=2c5e8b1f7a3d9604c8b2e5f7a1d39c68
KEY_RO=7b1d4e8a2c6f9035d7e1b8a4c2f60d93
```

Caller app-a through the proxy:

```bash
curl -s -H "X-CredProx-Key: $KEY_A" http://localhost:5083/
```

```
credprox-app-a
```

Caller app-b, same route, same credential config:

```bash
curl -s -H "X-CredProx-Key: $KEY_B" http://localhost:5083/
```

```
credprox-app-b
```

The protected API echoes the `azp` claim — the Keycloak client the token was minted for.
Two callers, two vendor accounts, zero code.

The read-only caller: GET allowed, POST blocked by its allow-list:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H "X-CredProx-Key: $KEY_RO" http://localhost:5083/
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H "X-CredProx-Key: $KEY_RO" http://localhost:5083/
```

```
200
403
```

And with no key at all:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:5083/
```

```
401
```

## The exact config

```jsonc
"CredProx": {
  "Callers": {
    "app-a":      { "Keys": [ { "KeyId": "app-a-key-1", "KeyHash": "sha256:dcb3aef7…" } ] },
    "app-b":      { "Keys": [ { "KeyId": "app-b-key-1", "KeyHash": "sha256:79581a6f…" } ] },
    "app-readonly": {
      "Keys": [ { "KeyId": "readonly-key-1", "KeyHash": "sha256:be4539ba…" } ],
      "Operations": [ { "Route": "api", "Methods": [ "GET" ] } ]
    }
  },
  "Credentials": {
    "keycloak": {
      "Type": "OAuthClientCredentials",
      "TokenEndpoint": "http://keycloak:8080/realms/credprox/protocol/openid-connect/token",
      "ClientId": "credprox-{partition}",
      "ClientSecret": "secret:keycloak-{partition}-secret",
      "TokenTypeName": "Bearer",
      "Partition": { "From": "caller:", "Allowed": [ "app-a", "app-b", "app-readonly" ] }
    }
  },
  "Secrets": {
    "keycloak-app-a-secret": "credprox-app-a-secret",
    "keycloak-app-b-secret": "credprox-app-b-secret",
    "keycloak-app-readonly-secret": "credprox-app-readonly-secret"
  },
  "Audit": { "Enabled": true }
}
```

The route carries `CredProx.Credential=keycloak`. `{partition}` is the whole trick: the
token cache keys per partition too, so app-a and app-b never see each other's tokens.

## Watch the audit records

```bash
docker compose logs proxy | grep credprox.audit
```

```
credprox.audit credprox.proxied_call: caller=app-a keyId=app-a-key-1 route=api vendor=api method=GET pathTemplate=/{**catch-all} status=200 latencyMs=41.2 bytes=15 credential=keycloak traceId=…
credprox.audit credprox.proxied_call: caller=app-b …
credprox.audit credprox.proxied_call: caller=app-readonly method=GET status=200 …
credprox.audit credprox.rejected_call: caller=app-readonly … method=POST status=403 …
```

Records carry the credential NAME (`keycloak`), never a secret value; the caller key value
never appears in any field even if its header is captured.

## About the demo keys

Caller keys must be **high-entropy random values** (128+ bits) — they are bearer secrets.
The registry stores them as **unsalted SHA-256 hashes**: that is a lookup index, not a
password store. A leaked config is only safe against offline cracking as long as the keys
themselves are unguessable; rotate by adding a second key entry and retiring the old one.

## Verify it

```bash
cd samples/PerCallerCredentials && ./smoke.sh
```

Checks both callers hit their own Keycloak account, the read-only allow-list (200 GET /
403 POST), keyless 401, and an audit record for each of the three callers in the proxy
logs. Prints `SMOKE OK`.

## What just happened

Tracing `curl -H "X-CredProx-Key: $KEY_A" http://localhost:5083/`:

1. Caller auth hashes the key and resolves it to `app-a` (constant-time over the hash).
2. The route's allow-list check passes (app-a has no restrictions; app-readonly's POST
   would stop here with 403).
3. The credential is partitioned `caller:` → partition value `app-a`; `ClientId` and
   `ClientSecret` templates expand `{partition}` to `credprox-app-a` / its secret.
4. CredProx fetches and caches a token **per partition** and forwards with it; the API
   validates the JWT and echoes `azp=credprox-app-a`.
5. The audit sink receives one record — caller, route, vendor, method, path template,
   status, latency, bytes, credential name, trace id — after the response completes.
