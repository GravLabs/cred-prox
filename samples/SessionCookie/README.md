# E16 — Session-cookie login: the generic Cayuse shape (plan §8.1)

Not every vendor speaks bearer tokens. A whole generation of enterprise APIs — the
Cayuse-class integrations that motivated this project (plan §2) — authenticate with a
form POST that answers `Set-Cookie`, then guard every call with that session cookie.
This sample is that vendor, made vendor-neutral: one `LoginExchange` credential logs in,
captures the session cookie, and replays it on every proxied call — **`Location: Cookie`
with no C# at all**, keeping the per-environment partitions, per-partition secrets and
strict allow-list that the original Cayuse demo needed (and fixing the bug class its
`Mode: Contains` header matching opened — F6).

## What it shows

- **Session-cookie login as pure config** (`CredProx:Credentials:crm`):
  `Type: LoginExchange`, `Method: POST` with `Form` credentials, `Response: Cookie` +
  `ResponseField: CRMSESSION` to capture the login's session cookie, and
  `Location: Cookie` to replay it. The credential is cached, refreshed on 401 and
  partitioned like every other type — nothing about cookie placement is special-cased
  in the pipeline. `Lifetime: 00:55:00` carries over the Cayuse assumed session lifetime.
- **Per-environment partitions** (`Partition: From header:X-API-Env`,
  `Allowed: [sandbox, production]`): one credential serves every environment. The
  `{partition}` template reaches the login endpoint, the service account
  (`svc-{partition}`) and the secret (`secret:crm-{partition}-pass`), so each
  environment logs in as itself and caches its own session (the smoke counts one
  issuance per environment across repeated calls).
- **The F6 bug class, closed by the allow-list**: the original Cayuse config matched
  the environment header with `Mode: Contains` before substituting it — a crafted
  header could point the proxy at a different host. Here `X-API-Env: sandbox-evil` is
  not on the allow-list and dies with `400 credprox.partition_not_allowed` before any
  login or forwarding. Allow-lists are exact matches, as a library guarantee.
- **The caller's cookies never reach the vendor**: cookie placement **replaces** the
  whole `Cookie` header, never merges — merging would smuggle the caller's own cookies
  to the vendor next to the session. The stub echoes the raw `Cookie` header it
  received into a `debug_cookie` field; a caller that sends
  `Cookie: theme=dark; CRMSESSION=caller-forged` still sees only
  `"debug_cookie":"CRMSESSION=[redacted]"` — its own pairs never arrived, and the real
  session is scrubbed (§8.2) from what did.
- **Server-side expiry is invisible** (refresh-on-401): when the vendor drops the
  session mid-run, its 401 triggers a re-login and one retry before the caller's
  response is written; the caller sees a plain 200 and exactly one extra login for
  that environment.
- **Vendor errors speak one dialect** (error normalisation, §8.5): the stock API's
  own `404 {"error":"SKU_NOT_FOUND",...}` reaches the caller as the uniform
  `application/problem+json` document — status kept, the vendor's payload preserved
  as the `vendor_detail` member (`extensions.code: credprox.vendor_error`) — so the
  caller's error handling sees one shape for proxy and vendor failures alike. The
  `/crm-raw/...` route carries `CredProx.ErrorNormalisation: "off"` and forwards the
  vendor's bytes exactly as written; the smoke checks both sides.
- **Nothing secret in sight**: the session value, the login passwords and the caller's
  own key are absent from every response body and every audit line; the audit records
  `caller=erp-integration route=crm status=200` — never a credential.

## Run the smoke (CI, no Docker)

```bash
dotnet run -- --smoke
```

The vendor is stubbed in-process and makes the checks the real one makes: the login
validates the form-posted per-environment credentials (wrong ones → 401, and no proxied
call gets a 200 without them) and issues the session cookie; the data API refuses
anything whose `CRMSESSION` is not the live session for that environment. The smoke
asserts: keyless and forged key → 401; sandbox call → 200 with `CRMSESSION=[redacted]`
in the echo and no session value anywhere; one login per environment across repeated
calls; production gets its own login and data; caller cookies replaced (neither
`theme=dark` nor a forged `CRMSESSION` reaches the vendor); `X-API-Env: sandbox-evil`
→ `400 credprox.partition_not_allowed`; a server-side expiry refreshes through the 401
transparently (exactly one extra issuance); the vendor's `SKU_NOT_FOUND` 404 arrives as
a normalised problem document on `/crm/...` and byte-as-written on the opted-out
`/crm-raw/...` route; and the audit shows `proxied_call` with no session value,
password or caller key in any line.

## Point it at a real session-cookie vendor

1. Put the per-environment accounts in your secret source (`crm-{partition}-pass` here;
   any `ISecretSource` works, as in the other samples).
2. Set the three vendor facts:
   - `CredProx:Credentials:crm:LoginEndpoint` → the real login URL, with
     `{partition}` wherever the environment appears (Cayuse itself used
     `signin.{partition}.vendor.com`);
   - `Form` → the vendor's field values (the provider posts `user`/`password`; for a
     vendor with other field names or Basic auth, switch to `Basic` or keep a tiny
     plugin credential — E10);
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
