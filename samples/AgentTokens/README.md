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
- The sample ships its own agent client (`Agent/`): a real tool-calling loop over the
  Anthropic Messages API — `tool_use` in, `tool_result` back — pointed at this host and
  holding nothing but its Entra token. The Anthropic key is a StaticKey credential
  (`x-api-key`) held by CredProx and attached on the model route; the agent never has it
  and never sees it. One tool (`fetch_docs`) is on the caller's allow-list; one
  (`github_meta`) deliberately is not, so the proxy answers 403 before connecting and the
  agent carries on with that refusal as a tool error — that is the admission demo.
- The model route opts in to usage metering by naming its usage format
  (`CredProx.Metering.Usage: "anthropic"`), so the provider's token counts are attributed
  to the calling agent, not to whoever holds the key.

`Program.cs` is the deployable host and nothing else: `AddCredProx(builder.Configuration)`
(one call for the core defaults — token cache, secret stack, credential binder) chained
with `.AddIdentity()` (arms the token path above, ADR-0004), the reverse proxy from
config, run. All policy lives in `appsettings.json`; the offline demo
values live in `appsettings.Development.json`. Replace the three `YOUR-*` placeholders and
the same host runs against your tenant.

## Packages to install

```bash
dotnet add package CredProx
dotnet add package CredProx.Identity
```

`CredProx.Abstractions` and the JWT bearer handler arrive transitively. A token-only host
needs nothing else: chaining `.AddIdentity()` arms the caller-token scheme and brings the
core caller policy with it (ADR-0004). The same proxy admits API-key callers through the
same core package — declare key hashes under `CredProx:Callers` and nothing more.

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
| `CredProx:Destinations:<name>:Template` | The real upstream each route may reach — the guard's allow-list. A route no operation names is refused with 403 before a connection is made (the `meta` route exists to show exactly that). |
| `CredProx:Credentials:<name>` | The model route's Anthropic key: `Type: StaticKey`, `Location: Header`, `Name: x-api-key`, `Secret: secret:anthropic-key`. CredProx attaches it outbound; the agent can neither read nor override it (an inbound `x-api-key` is stripped like the bearer). The route also SETS `anthropic-version: 2023-06-01` outbound — the agent sends no version header of its own, and an inbound one is replaced, not forwarded (both pinned by the AgentTokens smokes). |
| `CredProx:Secrets:<name>` | The key's value. Demo placeholder committed; supply the real one via your secret source (env `CredProx__Secrets__anthropic-key`, a vault provider, …) — never commit a live key. |
| route metadata `CredProx.Metering.Usage: "anthropic"` | The opt-in: the value NAMES the usage format (M54); readers declaring it parse this route's provider usage numbers, counted onto the calling agent's meter. |

A caller that lists `TokenClientIds` but names no operation rule logs a startup warning —
*this caller can never admit a token* — and starts anyway: the key path is unaffected, the
token path is closed by construction. Refusals are logged server-side with one of exactly
four reasons (`stale`, `unlisted`, `no named operation rule matched`, `the caller declares
no named operations`); the response body never carries one.

## Running it for real

1. **Expose the proxy API.** App registration "CredProx API" → *Expose an API* → application
   ID URI `api://YOUR-AGENT-API` (or your verified-domain URI). A tenant's default protection
   policy can refuse a name that is neither a verified domain nor an id — it accepts
   `api://<client-id>` always, so that is the safest choice. Add app roles **`docs-read`**
   and **`model-call`**, allowed for *Applications*. In the API's **Manifest**, set `requestedAccessTokenVersion`
   to `2`: a new registration issues v1 tokens by default, whose issuer
   (`https://sts.windows.net/<tenant>/`) does not match the v2 `Authority` above, so every
   token would be refused with 401. A v2 token's audience is the API's **client id** (a
   GUID, not the URI) — that is what `CredProx:CallerToken:Audience` must equal.
2. **Register the agent app** (or use its managed identity). Assign it **both** app roles,
   `docs-read` and `model-call` (*API permissions → Granted roles*, or Enterprise-app role
   assignment). Each gates its own route: `docs-read` is the role named by the GET docs
   rule, `model-call` the one named by the model rule (`POST /v1/messages`) — a token
   missing one is refused with 403 on that route before any vendor is touched. Entra
   then writes `"roles": ["docs-read", "model-call"]` into the app token it issues for
   that client. A fresh role assignment can lag issued tokens by seconds to minutes
   (same replication class as a fresh client secret): the live harness therefore polls
   for both roles to show up before its live cell, up to `CREDPROX_M46_ROLE_WAIT_SECONDS`
   (default 300).
3. **The agent gets a token with no stored secret** (needs the `Azure.Identity` package):
   - *On Azure (managed identity):*
     `new DefaultAzureCredential().GetTokenAsync(new TokenRequestContext(["api://YOUR-AGENT-API/.default"]))` —
     Azure.Identity fetches from the local IMDS; nothing to rotate.
   - *Off Azure (workload identity federation):* a federated credential on the agent's app
     maps the external assertion (Kubernetes service-account token, GitHub OIDC token, …)
     to the Entra app; Azure.Identity exchanges it for the same access token — again no
     secret to store.
4. **Fill the placeholders** in `appsettings.json`: your tenant id in `Authority`, the API's
   client id in `Audience`, the agent's client id in `TokenClientIds`. Don't set
   `RequireHttpsMetadata` — the default is what Entra needs.
5. **Give the host the Anthropic key** — `CredProx__Secrets__anthropic-key` (or your secret
   source). The model route already points at `api.anthropic.com`; nothing else to wire.
6. **Run the agent.** It authenticates with its own Entra token and speaks the Anthropic
   Messages protocol through the proxy:
   ```bash
   AGENT_TENANT_ID=... AGENT_CLIENT_ID=... AGENT_CLIENT_SECRET=... \
   AGENT_API_SCOPE=api://YOUR-AGENT-API/.default \
   dotnet run --project samples/AgentTokens/Agent
   ```
   A run makes a few billable Anthropic calls on your API credits — cheapest default model
   (`claude-haiku-5-5`, override with `AGENT_MODEL`), small `max_tokens`, fixed short prompt,
   so: cents. If you replace the raw-HttpClient loop with a vendor SDK, the SDK's mandatory
   key argument must be a visible placeholder that CredProx replaces on the way out — the
   agent process itself never holds a vendor secret either way.

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
upstream journal shows no `Authorization` header on any proxied request. A second file of
cells drives the actual `Agent.dll` against a scripted stand-in chain
(`tool_use` → `tool_use` → final answer): the allowed `fetch_docs` returns its document, the
`github_meta` call comes back to the agent as an HTTP 403 tool error while the loop carries
on, an unlisted `azp` or a missing `model-call` role stops the agent before the model, the
provider journal shows `x-api-key` attached on every `/v1/messages` record with no
`Authorization` among them, and the vendor key appears nowhere in the agent's output.
Nothing private is committed anywhere.

The samples restore CredProx from the local feed, so pack it once first (on a clean
machine):

```bash
dotnet pack src/CredProx.Abstractions -c Release -o artifacts/packages
dotnet pack src/CredProx -c Release -o artifacts/packages
dotnet pack src/CredProx.Identity -c Release -o artifacts/packages
dotnet pack src/CredProx.Operations -c Release -o artifacts/packages
```

Repacking the same version does not change its bytes' identity to NuGet: if you have packed
this version before, evict the cached copies first
(`rm -rf ~/.nuget/packages/credprox*`) or the check may run against stale packages.
