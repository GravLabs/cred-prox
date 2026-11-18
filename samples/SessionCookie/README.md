# Session-cookie login: the generic vendor shape

Not every vendor speaks bearer tokens. A whole generation of enterprise APIs
authenticate with a form POST that answers `Set-Cookie`, then guard every call with
that session cookie. This sample is that vendor, made vendor-neutral: one
`LoginExchange` credential logs in, captures the session cookie, and replays it on
every proxied call — **`Location: Cookie` with no C# at all**, with per-environment
partitions, per-partition secrets and a strict allow-list.

## What it shows

- **Session-cookie login as pure config** (`CredProx:Credentials:crm`):
  `Type: LoginExchange`, `Method: POST` with `Form` credentials, `Response: Cookie` +
  `ResponseField: CRMSESSION` to capture the login's session cookie, and
  `Location: Cookie` to replay it. The credential is cached, refreshed on 401 and
  partitioned like every other type — nothing about cookie placement is special-cased
  in the pipeline. `Lifetime: 00:55:00` carries a typical assumed session lifetime.
- **Per-environment partitions** (`Partition: From header:X-API-Env`,
  `Allowed: [sandbox, production]`): one credential serves every environment. The
  `{partition}` template reaches the login endpoint, the service account
  (`svc-{partition}`) and the secret (`secret:crm-{partition}-pass`), so each
  environment logs in as itself and caches its own session (the cells count one
  issuance per environment across repeated calls).
- **Why the allow-list is exact**: an environment header that is merely *substituted*
  into a login URL is an attack surface — a crafted value can point the proxy at a
  host you never configured. Here `X-API-Env: sandbox-evil` is not on the allow-list
  and dies with `400 credprox.partition_not_allowed` before any login or forwarding.
  Allow-lists are exact matches, as a library guarantee.
- **The caller's cookies never reach the vendor**: cookie placement **replaces** the
  whole `Cookie` header, never merges — merging would smuggle the caller's own cookies
  to the vendor next to the session. The stand-in echoes the raw `Cookie` header it
  received into a `debug_cookie` field; a caller that sends
  `Cookie: theme=dark; CRMSESSION=caller-forged` still sees only
  `"debug_cookie":"CRMSESSION=[redacted]"` — its own pairs never arrived, and the real
  session is scrubbed from what did.
- **Server-side expiry is invisible** (refresh-on-401): when the vendor drops the
  session mid-run, its 401 triggers a re-login and one retry before the caller's
  response is written; the caller sees a plain 200 and exactly one extra login for
  that environment.
- **Vendor errors speak one dialect** (error normalisation): the stock API's own
  `404 {"error":"SKU_NOT_FOUND",...}` reaches the caller as the uniform
  `application/problem+json` document — status kept, the vendor's payload preserved
  as the `vendor_detail` member (`extensions.code: credprox.vendor_error`) — so the
  caller's error handling sees one shape for proxy and vendor failures alike. The
  `/crm-raw/...` route carries `CredProx.ErrorNormalisation: "off"` and forwards the
  vendor's bytes exactly as written; the cells check both sides.
- **Nothing secret in sight**: the session value, the login passwords and the caller's
  own key are absent from every response body and every audit line; the audit records
  `caller=erp-integration route=crm status=200` — never a credential.

## Run it

```bash
cd samples/SessionCookie
(cd StubApi && dotnet run &)   # the vendor stand-in
dotnet run
```

Then call through the gateway for the sandbox environment:

```bash
curl -s http://localhost:5095/crm/api/contacts \
  -H 'X-CredProx-Key: credprox-e16-erp-demo-key' \
  -H 'X-API-Env: sandbox'
```

```
{"result":{"records":[{"id":1,"name":"Acme (sandbox CRM)"}],"env":"sandbox"},"debug_cookie":"CRMSESSION=[redacted]"}
```

Nobody sent a session cookie: the gateway logged in with the sandbox account, replayed
the `Set-Cookie` session, and the echo of that session arrives redacted.

## Verify it

```bash
cd samples/SessionCookie && ./smoke.sh
# or directly:
dotnet test tests/CredProx.SampleSmokes --filter Sample=SessionCookie
```

Eight cells against the stand-in: keyless and forged keys → 401 with no login; the
sandbox call → 200 with `CRMSESSION=[redacted]` in the echo and repeated calls riding
one cached login; production gets its own account, secret and login without touching
the sandbox session; caller cookies replaced wholesale (neither `theme=dark` nor a
forged `CRMSESSION` reaches the vendor); `X-API-Env: sandbox-evil` →
`400 credprox.partition_not_allowed`; a server-side expiry refreshes through the 401
transparently (exactly one extra issuance); the vendor's `SKU_NOT_FOUND` 404 arrives as
a normalised problem document on `/crm/...` and byte-as-written on the opted-out
`/crm-raw/...` route; and the audit on the host's own console shows `proxied_call`
with no session value, password or caller key in any line.

## Point it at a real session-cookie vendor

1. Put the per-environment accounts in your secret source (`crm-{partition}-pass` here;
   any `ISecretSource` works, as in the other samples).
2. Set the three vendor facts:
   - `CredProx:Credentials:crm:LoginEndpoint` → the real login URL, with
     `{partition}` wherever the environment appears (many vendors use the
     `signin.{partition}.vendor.com` shape);
   - `Form` → the vendor's field values (the provider posts `user`/`password`; for a
     vendor with other field names or Basic auth, switch to `Basic` or keep a tiny
     plugin credential like `samples/CustomPlugin`);
   - `ReverseProxy:Clusters:crm:Destinations:crm:Address` → the real API host (and a
     `Destinations` template with its own allow-list if the host varies per
     environment, as `samples/LoginExchange` shows).
3. Keep `Response: Cookie` + `ResponseField` when the session arrives via
   `Set-Cookie`, or `RawBody`/`JsonPath`/`Header` when it arrives elsewhere — placement
   and extraction are independent (`Location: Cookie` + `Response: JsonPath` is a
   legitimate mix for a vendor that hands a cookie-named token in JSON).
4. Call the API with `X-CredProx-Key: <caller key>` and `X-API-Env: <environment>`.
   CredProx logs in once per environment, replays the cookie, refreshes through 401s,
   and scrubs the session out of reflecting responses.

## What just happened (one request traced)

`GET /crm/api/contacts` with `X-CredProx-Key: <erp key>` and `X-API-Env: sandbox`
→ caller authentication resolves `erp-integration` from the key hash → the operation
allow-list admits `GET /crm/api/**` → the credential's partition source admits
`sandbox` (anything not exactly on the list, 400) → the `crm` credential hands over the
cached `sandbox` session cookie — on a cache miss it POSTs the login form with the
`{partition}`-resolved account and secret and reads `CRMSESSION` out of the `Set-Cookie`
— and registers the value with the response scrubber → placement **replaces** the
caller's entire `Cookie` header with `CRMSESSION=<session>` → the vendor answers; the
session its echo field reflects back arrives to the caller as `[redacted]`, and a
vendor-side 401 anywhere would re-login and retry before the caller noticed → the audit
sink records `caller=erp-integration route=crm status=200` with no credential in sight.
