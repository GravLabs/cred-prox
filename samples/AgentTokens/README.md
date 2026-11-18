# Agent tokens: your agents call the proxy with their Entra token

## What it shows

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

`Program.cs` is the deployable host and nothing else: `AddCredProx(builder.Configuration)`
(one call for the core defaults — token cache, secret stack, credential binder; ADR-0005
item 5), `AddCredProxCallerTokenAuthentication` (the token path above, ADR-0004), the
reverse proxy from config, run. All policy lives in `appsettings.json`; the offline demo
values live in `appsettings.Development.json`. Replace the three `YOUR-*` placeholders and
the same host runs against your tenant.

## Packages to install

```bash
dotnet add package CredProx
dotnet add package CredProx.CallerTokens
```

`CredProx.Abstractions` and the JWT bearer handler arrive transitively. A token-only host
needs nothing else: registering the token authenticator brings the core caller policy with
it (ADR-0004/0005). Add `CredProx.CallerKeys` only when the same proxy also admits API-key
callers.

## The config, key by key

| Key | Meaning |
|---|---|
| `CredProx:CallerToken:Authority` | Required. The OIDC issuer that signs agent tokens; its published metadata and keys validate them. Must be https in production. |
| `CredProx:CallerToken:Audience` | Required. A token minted for any other API is refused. |
| `CredProx:CallerToken:MaxTokenAge` | Optional. `d.HH:mm:ss`, measured from `iat`, greater than zero and under 24 h; enforced before claim mapping (beyond the handler's 5-minute clock skew). Unset means the issuer's own lifetime is the bound. Read at startup — changing it takes a restart. |
| `CredProx:CallerToken:RequireHttpsMetadata` | Optional, defaults to `true`, and the `false` opt-out is enforced: it starts only with an `Authority` that is http on a loopback host (`localhost`, `127.0.0.1`, `::1`) — the local issuer stub — and any other combination refuses startup naming both keys. A dev setting copied into a production config cannot quietly disable the safeguard. |
| `CredProx:CallerToken:ClientClaimNames` / `ScopeClaimNames` | Optional. Claim layouts other than Entra v2 (`appid` on v1, custom names). The scheme turns inbound claim mapping off, so whatever the issuer writes is what these lists match. |
| `CredProx:Callers:<name>:TokenClientIds` | The app (client) ids whose tokens map to this caller; match is verbatim against `azp`/`appid`. |
| `CredProx:Callers:<name>:Operations[].Name` | The rule's name; a token is admitted only where its `roles` claim carries it. |
| `CredProx:Destinations:<name>:Template` | Where the credential attaches. No secret here: this sample forwards the agent's own request untouched. |

A caller that lists `TokenClientIds` but names no operation rule logs a startup warning —
*this caller can never admit a token* — and starts anyway: the key path is unaffected, the
token path is closed by construction. Refusals are logged server-side with one of exactly
four reasons (`stale`, `unlisted`, `no named operation rule matched`, `the caller declares
no named operations`); the response body never carries one.

## Running it for real

1. **Expose the proxy API.** App registration "CredProx API" → *Expose an API* → application
   ID URI `api://YOUR-AGENT-API` (or your verified-domain URI). Add app role **`docs-read`**,
   allowed for *Applications*. The token audience is this URI (or the API's client id) —
   that is what `CredProx:CallerToken:Audience` must equal.
2. **Register the agent app** (or use its managed identity). Assign it the `docs-read`
   app role (*API permissions → Granted roles*, or Enterprise-app role assignment). Entra
   then writes `"roles": ["docs-read"]` into the app token it issues for that client.
3. **The agent gets a token with no stored secret** (needs the `Azure.Identity` package):
   - *On Azure (managed identity):*
     `new DefaultAzureCredential().GetTokenAsync(new TokenRequestContext(["api://YOUR-AGENT-API/.default"]))` —
     Azure.Identity fetches from the local IMDS; nothing to rotate.
   - *Off Azure (workload identity federation):* a federated credential on the agent's app
     maps the external assertion (Kubernetes service-account token, GitHub OIDC token, …)
     to the Entra app; Azure.Identity exchanges it for the same access token — again no
     secret to store.
4. **Fill the placeholders** in `appsettings.json`: your tenant id in `Authority`, the API
   URI in `Audience`, the agent's client id in `TokenClientIds`. Don't set
   `RequireHttpsMetadata` — the default is what Entra needs.

**Revocation** is Entra-side: remove the app-role assignment (or disable the SP / identity)
and the next token stops carrying the role or authenticating at all; tokens already issued
die within `MaxTokenAge + clock skew` at the latest — and the per-caller kill switch turns
off that caller immediately if you need faster than that.

## Running the offline check

No tenant, no network: two WireMock stubs stand in for the issuer (8085) and the upstream
(8086); `ASPNETCORE_ENVIRONMENT=Development` merges `appsettings.Development.json` over the
real shape, pointing the issuer, audience, client id and destination at them.

```bash
# one cell per behavior, driving the real host over real sockets:
dotnet test tests/CredProx.SampleSmokes --filter Sample=AgentTokens
# or the one-line wrapper:
samples/AgentTokens/smoke.sh
```

The check generates its signing key fresh in the test process, registers the public half as
the stub's JWKS through the admin API at priority 0, and fails if the issuer ever serves a
key other than the one that signed the tokens. It proves: stub serves the generated key
(kid check); fresh `docs-read` token as a string and as an array → 200; multi-role arrays
admit only what they name → 200/403; role naming no rule → 403; no `roles` claim → 403;
unlisted `azp` → 401; a token issued 2 h ago with `MaxTokenAge=00:15:00` → 401; and the
upstream journal shows no `Authorization` header on any proxied request. Nothing private is
committed anywhere.

The samples restore CredProx from the local feed, so pack it once first (on a clean
machine):

```bash
dotnet pack src/CredProx.Abstractions -c Release -o artifacts/packages
dotnet pack src/CredProx -c Release -o artifacts/packages
dotnet pack src/CredProx.CallerTokens -c Release -o artifacts/packages
```

Repacking the same version does not change its bytes' identity to NuGet: if you have packed
this version before, evict the cached copies first
(`rm -rf ~/.nuget/packages/credprox*`) or the check may run against stale packages.
