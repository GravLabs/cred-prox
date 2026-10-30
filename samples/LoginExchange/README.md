# E12 — LoginExchange: session logins, per-environment partitions, allow-list

## What it demonstrates

The vendor shape that has **no OAuth at all**: you POST a service account to a login
endpoint and get a session token back. Shown against a vendor-neutral WireMock stub
("acme") so the mechanism — not a vendor — is the subject:

- **`LoginExchange`** — form login (`user`/`password` fields), session id read from a
  JSON field of the response, attached **raw** (no `Bearer` prefix — the default
  `AttachPrefix` is empty, which is what session-cookie-style vendors expect).
- **Per-environment partitions** — the `{partition}` template in the login URL and the
  form user makes **one credential** serve many environments; each partition's session
  is cached separately.
- **The allow-list** — `Partition.Allowed` admits `uat` and `staging`; anything else
  (e.g. `prod`) is refused with a problem response **before any vendor call**.

## What you need

Docker (the WireMock stub on `:8082`). No accounts.

## Run it

```bash
cd samples/LoginExchange
docker compose up -d
dotnet run
```

**UAT** — the caller names the environment, not a credential:

```bash
curl -s -H 'X-API-Env: uat' http://localhost:5087/acme/api/v1/timeoff
```

```
Acme stub received: Authorization = sess-uat-svc
```

The session token came from a login exchange CredProx ran first: `POST /acme/uat/login`
with form user `uat-svc` (the `{partition}` template) and the secret password; the
`sessionId` field of the response is attached raw.

**Staging** — a different partition, a different session:

```bash
curl -s -H 'X-API-Env: staging' http://localhost:5087/acme/api/v1/timeoff
```

```
Acme stub received: Authorization = sess-staging-svc
```

**Prod** — blocked by the allow-list, before any vendor call:

```bash
curl -si -H 'X-API-Env: prod' http://localhost:5087/acme/api/v1/timeoff | head -6
```

```
HTTP/1.1 400 Bad Request
content-type: application/problem+json
...
{"status":400,"title":"The requested partition is not allowed.","code":"credprox.partition_not_allowed"}
```

## The exact config

```jsonc
"CredProx": {
  "Destinations": { "acme": { "Template": "http://localhost:8082" } },
  "Credentials": {
    "acme": {
      "Type": "LoginExchange",
      "LoginEndpoint": "http://localhost:8082/acme/{partition}/login",
      "Method": "POST",
      "Form": { "User": "{partition}-svc", "Password": "secret:acme-password" },
      "Response": "JsonPath", "ResponseField": "sessionId",
      "Lifetime": "01:00:00",
      "Partition": { "From": "header:X-API-Env", "Allowed": ["uat", "staging"] }
    }
  },
  "Secrets": { "acme-password": "demo-acme-password" }
}
```

The route carries `CredProx.Credential` metadata (`acme`); see `appsettings.json`. For a
vendor that wants `Authorization: Bearer <session>` instead of the bare token, set
`"AttachPrefix": "Bearer"` on the credential.

## Verify it

```bash
cd samples/LoginExchange && ./smoke.sh
```

Checks all three behaviors above and prints `SMOKE OK`.

## What just happened

Tracing `curl -H 'X-API-Env: uat' http://localhost:5087/acme/api/v1/timeoff`:

1. The route matches and names credential `acme`.
2. The credential declares a partition: CredProx reads `X-API-Env: uat` and checks it
   against `Allowed: ["uat", "staging"]` — admitted. (With `prod` the request stops here
   with a `credprox.partition_not_allowed` problem response; the vendor is never called.)
3. No cached session exists for partition `uat`, so CredProx runs the login exchange:
   `POST /acme/uat/login` with form fields `user=uat-svc` (template-expanded) and the
   resolved password, then reads `sessionId` from the JSON response and caches it for
   `Lifetime`.
4. The forwarded request carries `Authorization: sess-…` (raw, per the empty
   `AttachPrefix`).
5. A second request for `uat` within the lifetime skips step 3 entirely — and a request
   for `staging` runs its own login, cached separately.
