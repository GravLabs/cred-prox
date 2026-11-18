# OAuthKeycloak: OAuth client credentials, end to end

## What it demonstrates

The full OAuth loop with a **real Keycloak**: CredProx fetches client-credentials tokens,
caches them (one token serves a concurrent burst — single-flight), attaches them to
forwarded requests, and transparently refreshes when the upstream rejects a revoked token
(refresh-on-401). The API behind the proxy is `StubApi/`, a small vendor stand-in that
validates the tokens with ordinary ASP.NET JwtBearer — the sample itself is only the
CredProx host, and the proxy side is pure configuration.

## What you need

Docker (`docker compose up`). No accounts — Keycloak runs locally with an imported realm.
The client secret here is a throwaway value inside a container that exists only for this
example.

## Run it

```bash
cd samples/OAuthKeycloak
docker compose up -d --build      # Keycloak (:5103), protected API (:5082), proxy (:5099)
```

First request through the proxy — **no credential goes in**:

```bash
curl -s http://localhost:5099/secrets
```

```
Bearer [redacted]
```

That is the protected API echoing the `Authorization` header it received, with one
difference: the JWT CredProx obtained from Keycloak and attached is a secret, so response
scrubbing removes it from the caller's view before the body ever reaches them. The
raw token is the API's to know — `curl -s http://localhost:5082/seen` shows what it
actually received. Hitting Keycloak directly with the same path returns 401 — the API is
genuinely protected; only CredProx holds the client secret.

## The exact config

```jsonc
"CredProx": {
  "Destinations": { "api": { "Template": "http://api:8080" } },
  "Credentials": {
    "keycloak": {
      "Type": "OAuthClientCredentials",
      "TokenEndpoint": "http://keycloak:8080/realms/credprox/protocol/openid-connect/token",
      "ClientId": "credprox-api",
      "ClientSecret": "secret:keycloak-secret",
      "TokenTypeName": "Bearer"
    }
  },
  "Secrets": { "keycloak-secret": "credprox-api-secret" }
}
```

The route carries `CredProx.Credential=keycloak`. That is the entire vendor integration.

## Watch the interesting parts

```bash
# Same token on every request (cache) — the API's record, since the caller's echo is redacted:
curl -s http://localhost:5099/secrets >/dev/null; curl -s http://localhost:5082/seen-count   # 1

# Refresh-on-401: tell the API to reject the token it last accepted, then request again.
curl -s -X POST http://localhost:5082/revoke
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:5099/secrets   # 200 — CredProx refreshed
curl -s http://localhost:5082/seen-count                                 # 2 — a NEW token arrived
```

The `/revoke` endpoint is a deliberate stand-in for vendor-side revocation (real vendors
each have their own mechanism); what it demonstrates is CredProx's reaction to any 401:
invalidate the cached token, fetch a fresh one, retry once — the caller never sees the 401.

## Verify it

One cell per behavior, driving the real proxy and API processes over real sockets from
`tests/CredProx.SampleSmokes`. Keycloak runs from `docker-compose.yml`; the processes run
with `ASPNETCORE_ENVIRONMENT=Development`, whose `appsettings.Development.json` replaces
the compose-network hostnames with the exposed ports — no code change:

```bash
dotnet test tests/CredProx.SampleSmokes --filter Sample=OAuthKeycloak
# or the one-line wrapper:
cd samples/OAuthKeycloak && ./smoke.sh
```

The cells check the protected path, refresh-on-401 (a NEW token reaches the API after
`/revoke`), and that a 10-request concurrent burst all carry one token — proven against
the API's own record of distinct accepted tokens (cache + single-flight), since the
caller's echo shows the token redacted.

## What just happened

Tracing `curl http://localhost:5099/secrets`:

1. The route names credential `keycloak`; no cached token exists yet, so CredProx POSTs a
   client-credentials grant to Keycloak with Basic client auth and caches the result under
   its expiry.
2. The forwarded request carries `Authorization: Bearer <jwt>` to the protected API.
3. The API validates the JWT against Keycloak's JWKS (standard JwtBearer) and answers.
4. The next request reuses the cached token; concurrent first-time requests collapse into a
   single token fetch.
5. When the API 401s a revoked token, CredProx refreshes and retries once before the caller
   ever sees a response.
