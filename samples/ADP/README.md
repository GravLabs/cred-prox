# E6 — ADP: OAuth client credentials plus mTLS, as configuration

## What it demonstrates

ADP's vendor shape, written entirely in explicit configuration — no presets, no
vendor-specific C#:

- **OAuth client credentials** (`OAuthClientCredentials`): Basic client auth against
  ADP's token endpoint, `workforce` scope, bearer attachment.
- **mTLS on both calls** (real-vendor config): the client certificate ADP requires is
  used on the **token call** (`Connection` on the credential) *and* on the **API calls**
  (`CredProx.Connection` on the cluster) — one named connection, two attachment points.

Ships a WireMock mapping that mimics ADP, so it runs with no account. Switching to the
real endpoint is a config change (`--variant real`), not a code change.

## What you need

WireMock mode: Docker. Real-vendor mode: your ADP credentials.

## Run it (WireMock mode)

```bash
cd samples/ADP
docker compose up -d          # the vendor stub on :8081
dotnet run
```

The caller sends no credential:

```bash
curl -s http://localhost:5086/adp/api/v1/employees
```

```
ADP stub received: Authorization = Bearer [redacted]
```

CredProx fetched the token from the stub's `/adp/oauth2/token` (client-credentials grant,
Basic client auth) and attached it — the bearer itself never reaches the caller: response
scrubbing (§8.2) removes injected secrets from the caller's view, and the stub's own
WireMock journal (`GET http://localhost:8081/__admin/requests`) shows what truly arrived.

## The exact config

```jsonc
"CredProx": {
  "Destinations": { "adp": { "Template": "http://localhost:8081" } },
  "Credentials": {
    "adp": {
      "Type": "OAuthClientCredentials",
      "TokenEndpoint": "http://localhost:8081/adp/oauth2/token",
      "ClientId": "adp-client",
      "ClientSecret": "secret:adp-secret",
      "Scope": "workforce",
      "TokenTypeName": "Bearer"
    }
  },
  "Secrets": { "adp-secret": "demo-adp-secret" }
}
```

The route carries `CredProx.Credential` metadata (`adp`); see `appsettings.json`.

## Switching to the real vendor

```bash
export CredProx__Credentials__adp__ClientId=...           # from ADP
export CredProx__Secrets__adp-secret=...                  # from ADP
export CredProx__Secrets__adp-cert="$(cat adp-cert.pem)"  # cert+key PEM bundle
dotnet run -- --variant real
```

`appsettings.RealAdp.json` repoints the destination and adds:

```jsonc
"Connections": { "adp-mtls": { "ClientCertificate": "secret:adp-cert" } },
"Credentials": { "adp": { "Connection": "adp-mtls", ... } }   // mTLS on the TOKEN call
// and on the cluster:  "Metadata": { "CredProx.Connection": "adp-mtls" }  // mTLS on API calls
```

WireMock cannot enforce mTLS, so the stub mode leaves the connection out; the mechanism
itself is exercised end to end by `samples/MutualTls` and the nginx mTLS E2E test.

## Verify it

```bash
cd samples/ADP && ./smoke.sh
```

Checks the behavior above and prints `SMOKE OK`.

## What just happened

Tracing `curl http://localhost:5086/adp/api/v1/employees`:

1. The route matches and names credential `adp`.
2. No cached token exists, so CredProx POSTs `grant_type=client_credentials` (plus
   `scope=workforce`) to the token endpoint with `Authorization: Basic
   base64(clientId:clientSecret)` — the secret resolved from the `secret:` reference.
3. The forwarded request carries `Authorization: Bearer <token>`, cached for the token's
   lifetime; a second request within it skips the token call entirely.
4. In real-vendor mode both the token call and the forwarded call run over the `adp-mtls`
   connection — the same client certificate on each.
