# E6 — ADP: certificate-based client credentials, as configuration

## What it demonstrates

ADP's workforce-API shape written entirely in explicit configuration — no presets, no
vendor-specific C#. This mirrors a known-working integration: client credentials over
**mutual TLS on both hops**, with the certificate kept in the same shape a Key Vault
certificate stores it.

- **OAuth client credentials with Basic client auth** against
  `…/auth/oauth/v2/token?grant_type=client_credentials`.
- **One named mTLS connection, presented twice**: on the **token call**
  (`Connection` on the credential) *and* on the **API calls**
  (`CredProx.Connection` on the cluster).
- **Certificate as a base64 passwordless PKCS#12 (PFX)** in `CredProx:Secrets` — the
  exact format the Key Vault backing secret of a certificate object holds, so an
  existing vault certificate drops in unchanged. (A PEM bundle is auto-detected too —
  swap the value, nothing else changes.)
- **GET-only routing** (`/adp/{**catch-all}` → PathRemovePrefix → the vendor cluster),
  bearer attached and scrubbed from the caller's view. The route declares
  `"Methods": ["GET"]`; the restriction surfaces as the routing layer's refusal —
  measured live once, then pinned into `smoke.sh`: POST → 404 (no matching route),
  GET → 200. YARP owns route matching; the sample proves the shipped config's effect
  rather than re-implementing method routing.

The offline stack is honest about enforcement: nginx with `ssl_verify_client on` sits
in front of the WireMock stub **for the token path and the API paths**, so the
certificate requirement is real, and nginx's own access log names the verified subject
per path. Test certificates are generated at run time (`generate-certs.sh`); nothing
secret is committed.

## What you need

Docker. No accounts, no real certificate.

## Run it

```bash
cd samples/ADP
./generate-certs.sh           # sample CA + nginx server cert + base64 PFX bundles
docker compose up -d          # vendor stub :8081, KV stub :8082, mTLS nginx :8443
SSL_CERT_FILE=$PWD/certs/ca.crt dotnet run
```

The caller sends no credential:

```bash
curl -s http://localhost:5086/adp/api/v1/employees
```

```
ADP stub received: Authorization = Bearer [redacted] | client = CN=client-alpha
```

Three independent witnesses, one request:

- `client = CN=client-alpha` — the **upstream** (nginx injects the verified client DN,
  the stub echoes it) names the certificate that arrived.
- `Bearer [redacted]` — the token was attached on the wire and scrubbed caller-side;
  the stub's journal (`GET http://localhost:8081/__admin/requests`) shows the raw
  bearer on the proxied request only.
- `docker compose logs nginx` — one line per request: the subject, on the token path
  and on the API path.

## The exact config

```jsonc
"CredProx": {
  "Destinations": { "adp": { "Template": "https://localhost:8443" } },
  "Connections": {
    "adp-mtls": { "ClientCertificate": "secret:adpClientCert" }   // base64 PFX
  },
  "Credentials": {
    "adp": {
      "Type": "OAuthClientCredentials",
      "TokenEndpoint": "https://localhost:8443/auth/oauth/v2/token?grant_type=client_credentials",
      "ClientId": "adp-client",
      "ClientSecret": "secret:adpClientSecret",
      "ClientAuthentication": "BasicHeader",     // default: Basic base64(clientId:clientSecret)
      "Connection": "adp-mtls"                   // mTLS on the TOKEN call
    }
  }
}
// and on the cluster:  "Metadata": { "CredProx.Connection": "adp-mtls" }   // mTLS on API calls
```

### Wire shape (measured, not assumed)

The token call this sample puts on the wire, recorded from the stub's journal by
`smoke.sh` into `bin/wire-check.txt` (per-run, untracked). The committed
`samples/ADP/wire-check.txt` is the curated artifact from a green run, and `smoke.sh`
asserts the fresh recording matches it byte for byte:

```
POST /auth/oauth/v2/token?grant_type=client_credentials
Authorization: Basic base64(clientId:clientSecret)
content-type: application/x-www-form-urlencoded
grant_type=client_credentials
```

The configured URL is sent verbatim (so the query-string grant travels), and CredProx
additionally sends the RFC 6749 form-body grant. The known-working original sent the
same URL with an empty body. The extra body parameter is the only difference; a
real-vendor smoke is the remaining check of ADP's acceptance.

No `scope` is sent (the original sent none); add `"Scope": "..."` only if your ADP
tenant asks for one. Token refresh follows CredProx's cache policy (refresh at 80 % of
lifetime, 30 s before expiry — earlier than the original's 5-minute rule, never later).

## Key Vault variant

```bash
export KeyVault__Uri=https://<your-vault>.vault.azure.net/
dotnet run -- --variant kv
```

Secrets then come from Azure Key Vault through the stock configuration provider
(`Azure.Extensions.AspNetCore.Configuration.Secrets`), with `ReloadInterval` set
explicitly — **the provider never polls without it** (the default is null = off).
Vault object names are config keys: a certificate named
`CredProx--Secrets--adpClientCert` lands as `CredProx:Secrets:adpClientCert`.

The right home for the certificate is a **Key Vault certificate object**: every
certificate also creates a secret with the same name, and for an exportable PKCS#12
policy that secret's value is the base64 PFX — the same `adp-auth-cert`-style blob,
auto-renewable, read here as a plain secret. On rotation the provider re-reads on its
reload interval and the connection registry swaps the certificate onto new
connections — no restart.

`./smoke.sh` proves exactly that **offline**: the same provider runs against a loopback
stub (only the transport is swapped), the stub swaps the served PFX mid-run with a
bumped `attributes.updated` — the signal a real rotation carries — and the next request
presents the new certificate. No Azure account is involved; a real-vault run is still
its own check.

## Switching to the real vendor

```bash
export CredProx__Credentials__adp__ClientId=...              # from ADP
export CredProx__Secrets__adpClientSecret=...                     # from ADP
export CredProx__Secrets__adpClientCert="$(cat adp-auth-cert.b64)"  # base64 PFX, no password
dotnet run -- --variant real
```

`appsettings.RealAdp.json` repoints the credential to
`https://accounts.adp.com/auth/oauth/v2/token?grant_type=client_credentials` and the
cluster to `https://api.adp.com/`, keeping the same `adp-mtls` connection on both. If
your PFX is password-protected, add
`"ClientCertificatePassword": "secret:adpCertPassword"`.

**Where each value comes from.** The real-vendor file commits only endpoint facts — it
deliberately declares no `ClientId` and no `Secrets` keys, so the values you export
above (or keep in user-secrets, or serve through `--variant kv`) reach the app
untouched; a source cannot shadow a key it does not declare. `--variant kv` takes the
vault endpoint itself from `KeyVault__Uri` and refuses at startup, naming
`KeyVault:Uri`, when it is missing. `samples/ADP/variant-guard.sh` (run by `smoke.sh`)
watches all three behaviors.

**Why these secret names are camelCase.** A secret key becomes an environment variable
(`CredProx__Secrets__<name>`), and bash `export` refuses names containing hyphens — a
hyphenated name (as this README documented before 0.9.3) aborts `export` with
"not a valid identifier" and the secret silently never arrives. `adpClientSecret` and
`adpClientCert` export cleanly in every mainstream shell, so the commands above work
exactly as written.

## Verify it

```bash
cd samples/ADP && ./smoke.sh
```

Checks the behaviour above — certificate on both hops, bearer attached + scrubbed,
certificateless run fails cleanly with no key material in the output, Key Vault
rotation witness — and prints `SMOKE OK`.

## What is verified offline vs what needs the real account

Verified here: configuration shape, enforcement of the client certificate on both
hops, bearer attach/scrub, refusal without a certificate, PFX handling from config and
from the Key Vault provider, live certificate rotation.

Needs a real ADP account: ADP's acceptance of the token request body CredProx sends
(the form-body grant in addition to the query), real token lifetimes, and any tenant
`scope` requirements. Needs a real vault: managed-identity auth to your vault.
