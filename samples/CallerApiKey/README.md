# E18 — Caller API keys: authenticating the callers of your proxy

## What it demonstrates

The other side of the credential story: vendor credentials go **out**, and this sample
shows who is allowed **in**. Callers present an `X-API-Key`; CredProx validates it before
any upstream call happens, and strips it so the upstream never sees it.

- **Key enforcement as config** — every CredProx route requires the caller key unless a
  route opts out with `CredProx.Caller: "anonymous"` metadata.
- **Secret-backed validation** — the store holds SHA-256 hashes compared in constant
  time; the hash declaration is itself a `secret:` reference, so no key material sits in
  a route match or config literal.
- **Indistinguishable refusals** — a missing key and a wrong key both get the same 401,
  and nothing about the presented key is echoed back, so the endpoint cannot be used to
  enumerate valid keys.
- **Header hygiene** — the inbound key header is removed before forwarding; the stub's
  request journal proves it never arrives.

## What you need

Docker (the upstream stub). No accounts.

## Run it

```bash
cd samples/CallerApiKey
docker compose up -d          # the upstream stub on :8081
dotnet run
```

Rejected, with no key:

```bash
curl -si http://localhost:5087/api/data | head -1     # HTTP/1.1 401 Unauthorized
```

Accepted with the demo key (its hash is committed in `appsettings.json`; the key itself
lives only in this README and the smoke):

```bash
curl -s -H 'X-API-Key: demo-caller-key-2026' http://localhost:5087/api/data
```

```
upstream received the request
```

The stub never received `X-API-Key` — check its journal:

```bash
curl -s http://localhost:8081/__admin/requests | grep -c X-API-Key    # 0
```

## The exact config

```jsonc
"CredProx": {
  "CallerAuth": { "HeaderName": "X-API-Key" },        // default: X-CredProx-Key
  "Callers": {
    "demo-app": {
      "Keys": [
        { "KeyId": "key-1", "KeyHash": "secret:demoAppKeyHash" }   // sha256:<64 hex>
      ]
    }
  },
  "Secrets": { "demoAppKeyHash": "sha256:52f4...e654" }            // env-inject the real one
}
```

Production posture: keep the hash in your secret store (env var
`CredProx__Secrets__demoAppKeyHash` or a vault secret — the key is camelCase so that
variable name exports cleanly in bash, which a hyphenated name would not), give every
caller its own `KeyId`, and set `ExpiresAt` per key to schedule rotation:

```jsonc
{ "KeyId": "key-2026", "KeyHash": "secret:demoAppKeyHash", "ExpiresAt": "2027-01-01T00:00:00Z" }
```

An expired key fails exactly like an unknown one. Hashes are of the raw key:
`sha256:$(printf %s "$KEY" | sha256sum | cut -d' ' -f1)`.

## Verify it

```bash
cd samples/CallerApiKey && ./smoke.sh
```

Checks: missing key → 401; wrong key → the same 401 with nothing echoed; valid key →
proxied 200; the stub journal shows the key header never reached the upstream. Prints
`SMOKE OK`.

## Deliberately not shown here

Caller *operation* allow-lists and rate limits (`Operations`, `Limits` under the caller)
— see `samples/PerCallerCredentials` for per-caller credential binding. ADP's example
(`samples/ADP`) does **not** require a caller key; the two features are independent.
