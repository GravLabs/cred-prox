# E19 — Agent tokens: your agents call the proxy with their Entra token

## What it demonstrates

An agent (a daemon, a worker, a CLI) calls CredProx with an **OIDC access token** instead of
a stored secret — Entra-first, but any OIDC issuer works the same way (ADR-0004):

- CredProx validates the token with the stock ASP.NET Core JWT bearer handler: signature,
  issuer, audience and expiry, with keys discovered from the authority's metadata. CredProx
  mints nothing; whoever signs is whoever validates against.
- The token's client claim (`azp`, or `appid` on v1 tokens) must be listed in a defined
  caller's `TokenClientIds`. A valid token from an app nobody configured is not a caller: 401.
- Caller tokens require named rules: a token gets exactly the operations its roles name;
  a caller without named rules admits no token. The token's Entra **app roles** (`roles`
  claim) intersect the caller's **named** operation rules and never widen them: a role
  naming no rule matches nothing — 403, the same refusal the operation allow-list gives
  an API-key caller.
- `MaxTokenAge` caps token age from `iat` even while the issuer still considers the token
  valid — staleness gets a kill window shorter than Entra's own lifetime policy.
- The caller's bearer token never reaches the upstream: CredProx strips `Authorization`
  after authenticating (journal-proven below).

## Run it (offline, no tenant)

The issuer is a WireMock stub publishing an OpenID configuration; its signing key is
**generated inside the smoke process at startup** (`Program.cs`) and its public half is
registered as the stub's JWKS through the admin API — nothing private is committed, and the
smoke fails if the issuer ever serves a key other than the one that signed the tokens. No
live tenant is involved; a live Entra run needs the owner's approval (plan §8.2).

```bash
# from the repo root — all four packages; CredProx restores CredProx.Abstractions from the
# same feed, so packing only src/CredProx fails NU1101 on a clean machine.
dotnet pack src/CredProx.Abstractions -c Release -o artifacts/packages
dotnet pack src/CredProx -c Release -o artifacts/packages
dotnet pack src/CredProx.AzureKeyVault -c Release -o artifacts/packages
dotnet pack src/CredProx.Testing -c Release -o artifacts/packages
cd samples/AgentTokens && ./smoke.sh
```

Repacking the same version does not change its bytes' identity to NuGet: if you have packed
this version before, evict the cache first (`rm -rf ~/.nuget/packages/credprox
~/.nuget/packages/credprox.abstractions ~/.nuget/packages/credprox.azurekeyvault
~/.nuget/packages/credprox.testing`) or the smoke may run against stale packages.

`smoke.sh` proves: the stub serves the run's generated key (kid check); fresh `docs-read`
token as a string and as an array → 200; multi-role arrays admit only what they name →
200/403; role naming no rule → 403; no `roles` claim → 403; unlisted `azp` → 401; token
issued 2 h ago with `MaxTokenAge=00:15:00` → 401; the upstream journal shows no
`Authorization` header on any proxied request.

## The exact config

```json
"CredProx": {
  "CallerToken": {
    "Authority": "http://localhost:8085",
    "Audience": "credprox-agent-api",
    "MaxTokenAge": "00:15:00"
  },
  "Callers": {
    "doc-reader": {
      "TokenClientIds": [ "demo-agent-client" ],
      "Operations": [
        { "Route": "docs", "Methods": [ "GET" ], "Paths": [ "/docs/**" ], "Name": "docs-read" }
      ]
    }
  }
}
```

`Authority` and `Audience` are required. `MaxTokenAge` is optional (unset = the issuer's
lifetime is the bound); a set value is written as `d.HH:mm:ss`, must be greater than zero
and under 24 hours (registration refuses anything else), and is read at startup — changing
it takes a restart. It is enforced before any claim mapping: a token whose `iat` is older
than the limit, beyond the 5-minute clock skew the JWT handler allows, gets 401 whatever
its roles say. `Authority` must be an https URL in production; the offline-only
`RequireHttpsMetadata = false` mutation in `Program.cs` is sample plumbing, not a pattern.
Hosts that replace the claim layout (v1 `appid`, non-Entra names) override
`ClientClaimNames`/`ScopeClaimNames` — the scheme turns inbound claim mapping off, so
whatever the issuer writes is what these lists match.

A caller that lists `TokenClientIds` but names no operation rule logs a startup warning —
*this caller can never admit a token* — and starts anyway: the key path is unaffected, the
token path is closed by construction. Refusals are logged server-side with one of exactly
four reasons (`stale`, `unlisted`, `no named operation rule matched`, `the caller declares
no named operations`); the response body never carries one.

## Entra setup (the real tenant)

1. **Expose the proxy API.** App registration "CredProx API" → *Expose an API* → application
   ID URI `api://credprox` (or your verified-domain URI). Add app role **`docs-read`**,
   allowed for *Applications*. The token audience is this URI (or the API's client id) —
   that is what `CredProx:CallerToken:Audience` must equal.
2. **Register the agent app** (or use its managed identity). Assign it the `docs-read`
   app role (*API permissions → Granted roles*, or Enterprise-app role assignment). Entra
   then writes `"roles": ["docs-read"]` into the app token it issues for that client.
3. **The agent gets a token with no stored secret** (needs the `Azure.Identity` package):
   - *On Azure (managed identity):*
     `new DefaultAzureCredential().GetTokenAsync(new TokenRequestContext(["api://credprox/.default"]))` —
     Azure.Identity fetches from the local IMDS; nothing to rotate.
   - *Off Azure (workload identity federation):* a federated credential on the agent's app
     maps the external assertion (Kubernetes service-account token, GitHub OIDC token, …)
     to the Entra app; Azure.Identity exchanges it for the same access token — again no
     secret to store.
4. **Point CredProx at the tenant:**

```json
"CallerToken": {
  "Authority": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "Audience": "api://credprox",
  "MaxTokenAge": "00:15:00"
}
```

and list the agent's client id under the matching caller's `TokenClientIds` (v2 tokens
carry it as `azp`; v1 tokens as `appid`).

**Revocation** is Entra-side: remove the app-role assignment (or disable the SP / identity)
and the next token stops carrying the role or authenticating at all; tokens already issued
die within `MaxTokenAge + clock skew` at the latest — and the per-caller kill switch turns
off that caller immediately if you need faster than that.

## Verify it

`./smoke.sh` ends with `SMOKE OK: generated signing key served by the stub, agent token
admitted as string and array (200), multi-role arrays admit only what they name (200/403),
unlisted role and roleless tokens 403, unlisted client and stale token 401, bearer token
stripped before forwarding.`

## Deliberately not shown here

Delegated (user) tokens (`scp` instead of `roles`) — the same `ScopeClaimNames` default
covers them, but the naming flow is a different story. Multi-tenant validation, per-tenant
authority resolution, and the key-rollover timing are covered by the library tests.
The deferred built-in issuer (CredProx signing tokens itself) is out of scope: Entra, or
any OIDC issuer, is the issuer.
