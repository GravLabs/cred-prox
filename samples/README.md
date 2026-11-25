# CredProx examples

Each example is a small, runnable ASP.NET Core host with its own README: what it
demonstrates, what you need, the exact config, and a `curl` showing the request **without**
a credential going in and the upstream receiving one. Vendor integrations are **config
only**, with no vendor-specific C#.

**Start here:** AgentTokens for AI agents on Entra, then AgentEgress, AiGateway,
MicrosoftGraph, OAuthKeycloak, ADP, TokenExchange and CallerApiKey. QuickStart is the
smallest host. The README's "Start here" table maps each one to the problem it solves.
Every host is a short config-driven `Program.cs` and a `smoke.sh` that runs the sample's
cells from `tests/CredProx.SampleSmokes`, with the vendor stood in locally — per page that
stand-in is a `StubApi/` project, a `wiremock/` mapping set, nginx in a compose file, or an
in-process stub. The offline repoint is page-specific too: some hosts' shipped
`appsettings.json` already points at the stub; the others repoint through
`appsettings.Development.json`, the compose files, the page's own `export` lines, or the
sample's own smoke cells.

| Project | Demonstrates | Needs | Verified by |
|---------|--------------|-------|-------------|
| [QuickStart](QuickStart/README.md) | Smallest host; `StaticKey` into a public echo service | Nothing | `./smoke.sh` |
| [OAuthKeycloak](OAuthKeycloak/README.md) | `OAuthClientCredentials` end to end; cache, single-flight, refresh-on-401 | Docker | `./smoke.sh` |
| [MutualTls](MutualTls/README.md) | Client certificate per cluster + live rotation; BadSSL variant | Docker (local) / nothing (badssl) | `./smoke.sh` |
| [MicrosoftGraph](MicrosoftGraph/README.md) | Entra client credentials in explicit config **and** secretless `TokenCredential`, one host with the style chosen by config; Key Vault secret source | Entra app (+Azure for identity); Docker for the offline check | `./smoke.sh` |
| [ADP](ADP/README.md) | ADP's shape as config, the original certificate arrangement: OAuth client credentials (Basic auth, query-string grant kept verbatim) + **one named mTLS connection on both the token call and the API calls**, certificate as a base64 passwordless PFX (the Key Vault certificate backing-secret format); nginx enforces the certificate offline; Key Vault variant with an offline live-rotation witness; measured wire shape recorded | Docker (nginx mTLS + WireMock + offline KV stub) | `./smoke.sh` |
| [PerCallerCredentials](PerCallerCredentials/README.md) | Caller keys, per-caller credential/operation allow-lists, audit redaction | Docker (Keycloak) | `./smoke.sh` |
| [GitHubApp](GitHubApp/README.md) | `JwtAssertion` in `BearerExchange` mode, all in config: app JWT → installation token → GitHub REST; the vendor stand-in verifies the minted JWT independently, the raw token is witnessed at the vendor while the caller sees it redacted | Nothing (stub project) / GitHub App (live) | `./smoke.sh` |
| [HmacSigning](HmacSigning/README.md) | `Hmac` request signing: canonical-string config, buffering cap → 413 | Nothing | `./smoke.sh` |
| [CustomPlugin](CustomPlugin/README.md) | A custom credential type in ~50 lines, registered explicitly, passing the `CredProx.Testing` conformance suites (run as a cell) | Nothing (stub project) | `./smoke.sh` |
| [Operations](Operations/README.md) | Throttling under load, vendor 429 + `Retry-After` pause, circuit breaker → 503, credential health checks | Docker (WireMock) | `./smoke.sh` (shortened load script) |
| [LoginExchange](LoginExchange/README.md) | Vendor-neutral session login: `LoginExchange` + `{partition}` per-environment partitions + the partition allow-list | Docker (WireMock stub) | `./smoke.sh` |
| [AiGateway](AiGateway/README.md) | AI provider gateway: caller keys in, provider key injected (`StaticKey`), per-caller operation allow-lists and budgets, cluster throttling, audit — SSE streaming passthrough proven by timing, the echoed key redacted inside the stream | Nothing (stub project) | `./smoke.sh` |
| [AzureOpenAI](AzureOpenAI/README.md) | Azure OpenAI gateway, keyless: caller keys in, a short-lived Entra token out (`TokenCredential`, scope `cognitiveservices.azure.com/.default`, managed identity or az sign-in), per-caller deployment allow-lists because the deployment rides the path, and per-caller token metering on the OpenAI `usage` object | Nothing (stub project); a real run needs your resource plus an inference role | `./smoke.sh` |
| [FoundryLocalGateway](FoundryLocalGateway/README.md) | Local-model gateway: a Foundry Local server on loopback authenticates nothing, so caller keys are the only gate; per-caller operation allow-lists refuse before the model is touched, and OpenAI usage is metered per caller through the route's `CredProx.Metering.Usage` format (inline JSON usage and the usage-only SSE event) — no upstream credential anywhere | Nothing (stub project); or a local Foundry Local on 127.0.0.1:5273 | `./smoke.sh` |
| [FoundryLocalCloud](FoundryLocalCloud/README.md) | Local plus cloud behind one front: a local Foundry Local route every caller may take and a cloud (Anthropic) route only named callers' allow-lists reach — the choice is routes and allow-lists, never code, and a dead local model fails the local call with no reroute; each route meters its own vendor's usage format, and the cloud key rides only the cloud hop | Nothing (stub project) | `./smoke.sh` |
| [FoundryLocalAgent](FoundryLocalAgent/README.md) | The M53 agent pattern on a local model: a bare OpenAI-format agent loop holding its own Entra caller token, its tools behind the same gate, named rules × token roles as the tool boundary (an omitted tool is refused 403 at the gate and reaches the model as a tool error; an unmapped client id gets 401), the thinking-model shape (empty content beside `reasoning_content`) handled as normal, an ~800-token completion budget and CPU-speed timeouts | Nothing (stub project, issuer included) | `./smoke.sh` |
| [TokenExchange](TokenExchange/README.md) | `TokenExchange` (Rfc8693) against real Keycloak: inbound user token validated (signature/issuer/audience/lifetime), exchanged per user for a downstream-audience token; the downstream's audience check proves the inbound token never reaches it; forged inbound → 401 | Docker (Keycloak 26.2) | `./smoke.sh` |
| [AgentEgress](AgentEgress/README.md) | AI agent egress (MCP shape): per-agent caller keys, allow-lists as tool boundaries, Salesforce `FormPost` client auth, one shared cached session token across agents, response scrubbing removing the token the stand-in echoes back | Nothing (stub project) | `./smoke.sh` |
| [SessionCookie](SessionCookie/README.md) | Session-cookie login (the generic Cayuse shape): form login → `Set-Cookie` replayed via `Location: Cookie` (caller cookies replaced, never merged), `{partition}` per-environment accounts/secrets with a strict `X-API-Env` allow-list, transparent refresh through server-side expiry, scrubbed session echo, vendor 404 normalised to `problem+json` (with a per-route opt-out) | Nothing (stub project) | `./smoke.sh` |
| [AzureContainerApps](AzureContainerApps/README.md) | Container Apps deployment host: the managed identity reaches Key Vault (stock provider, explicit reload) and feeds the caller-key hash and the vendor `StaticKey` — nothing secret on disk; caller keys at an internal ingress, health probes, scrubbed vendor echo; the live-gate harness (one image, four roles, its own in-image smoke) lives at `tools/aca-live-harness` | Nothing (stub project); Azure (managed identity + Key Vault) for the live run | `./smoke.sh` |
| [CallerApiKey](CallerApiKey/README.md) | Caller API keys as config: `X-API-Key` validated against a secret-backed SHA-256 store, 401 missing == 401 wrong with nothing echoed, key stripped before forwarding (journal-proven) | Docker (WireMock stub) | `./smoke.sh` |
| [AgentTokens](AgentTokens/README.md) | AI agents with no stored secret: the agent gets a short-lived Microsoft Entra access token (managed identity / workload identity federation, Azure.Identity). CredProx validates it, maps the client (`azp`) to a caller and admits only the operations its app roles name (named rules, never wider); `MaxTokenAge` refuses stale tokens and the bearer is stripped before forwarding. Includes the Entra setup | Docker (locally signed OIDC issuer + upstream stub, offline); an Entra tenant for a live run | `./smoke.sh` |

The library ships **no built-in vendor presets**: every vendor above is one
isolated sample whose full setup is plain config. A community preset
(`CredProx:Presets` or a custom `IPresetSource`) can package a sample's fixed facts for
reuse; see CONTRIBUTING.md.

## Before you build: pack the packages

Examples consume CredProx **as NuGet packages** (the quality bar — this is what catches
packaging mistakes), restored from the local feed `artifacts/packages` via
`samples/nuget.config`:

```bash
for p in src/*/; do dotnet pack "$p" -c Release -o artifacts/packages; done
```

(Or just run the CI `examples` job's first step. Once a version is published to a real
feed, `samples/nuget.config` drops the local source.)

## No real secrets, ever

Examples read secrets from environment variables or user-secrets and fail at startup naming
the exact missing value. Demo values that do appear (QuickStart's static key,
OAuthKeycloak's container-local Keycloak client, ADP's WireMock stubs) are throwaway:
on each page's documented offline path they only ever talk to local stubs, and where a
shipped `appsettings.json` names a real vendor, that page's offline path repoints at the stub.
