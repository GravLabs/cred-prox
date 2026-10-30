# CredProx examples (plan §6)

Each example is a small, runnable ASP.NET Core host with its own README: what it
demonstrates, what you need, the exact config, and a `curl` showing the request **without**
a credential going in and the upstream receiving one. Vendor integrations are **config
only** — no vendor-specific C#.

| # | Project | Demonstrates | Needs | Verified by |
|---|---------|--------------|-------|-------------|
| E1 | [QuickStart](QuickStart/README.md) | Smallest host; `StaticKey` into a public echo service | Nothing | `-- --smoke` (in-process) or `./smoke.sh` (WireMock) |
| E2 | [OAuthKeycloak](OAuthKeycloak/README.md) | `OAuthClientCredentials` end to end; cache, single-flight, refresh-on-401 | Docker | `./smoke.sh` |
| E3 | [MutualTls](MutualTls/README.md) | Client certificate per cluster + live rotation; BadSSL variant | Docker (local) / nothing (badssl) | `./smoke.sh` |
| E4 | [Spotify](Spotify/README.md) | A real public vendor in explicit config: `OAuthClientCredentials` + Basic client auth + two host values | Free Spotify app | build (nightly smoke with creds) |
| E5 | [MicrosoftGraph](MicrosoftGraph/README.md) | Entra client credentials in explicit config **and** secretless `TokenCredential`; Key Vault secret source | Entra app (+Azure for identity) | build (nightly smoke with creds) |
| E6 | [ADP](ADP/README.md) | ADP's shape as config: OAuth client credentials + mTLS on both the token call and the API calls (real-vendor variant) | Docker (WireMock stub) | `./smoke.sh` |
| E7 | [PerCallerCredentials](PerCallerCredentials/README.md) | Caller keys, per-caller credential/operation allow-lists, audit redaction | Docker (Keycloak) | `./smoke.sh` |
| E8 | [GitHubApp](GitHubApp/README.md) | `JwtAssertion` in `BearerExchange` mode, all in config: app JWT → installation token → GitHub REST | Nothing (stub mode) / GitHub App (live) | `-- --smoke` (in-process stubs) |
| E9 | [HmacSigning](HmacSigning/README.md) | `Hmac` request signing: canonical-string config, buffering cap → 413 | Nothing | `-- --smoke` (in-process verifier stub) |
| E10 | [CustomPlugin](CustomPlugin/README.md) | A custom credential type in ~50 lines, registered explicitly, passing the `CredProx.Testing` conformance suites | Nothing | `./smoke.sh` (selftest + in-process stubs) |
| E11 | [Operations](Operations/README.md) | Throttling under load, vendor 429 + `Retry-After` pause, circuit breaker → 503, credential health checks | Docker (WireMock) | `./smoke.sh` (shortened load script) |
| E12 | [LoginExchange](LoginExchange/README.md) | Vendor-neutral session login: `LoginExchange` + `{partition}` per-environment partitions + the partition allow-list | Docker (WireMock stub) | `./smoke.sh` |
| E13 | [AiGateway](AiGateway/README.md) | AI provider gateway: caller keys in, provider key injected (`StaticKey`), per-caller operation allow-lists, cluster throttling, audit — SSE streaming passthrough proven by timing | Nothing (in-process provider stub) | `-- --smoke` (in-process) |
| E14 | [TokenExchange](TokenExchange/README.md) | `TokenExchange` (Rfc8693) against real Keycloak: inbound user token validated (signature/issuer/audience/lifetime), exchanged per user for a downstream-audience token; the downstream's audience check proves the inbound token never reaches it; forged inbound → 401 | Docker (Keycloak 26.2) | `./smoke.sh` |
| E15 | [AgentEgress](AgentEgress/README.md) | AI agent egress (MCP shape): per-agent caller keys, allow-lists as tool boundaries, Salesforce `FormPost` client auth, one shared cached session token across agents, response scrubbing removing the token the stub echoes back | Nothing (in-process Salesforce stub) | `-- --smoke` (in-process) |
| E16 | [SessionCookie](SessionCookie/README.md) | Session-cookie login (the generic Cayuse shape): form login → `Set-Cookie` replayed via `Location: Cookie` (caller cookies replaced, never merged), `{partition}` per-environment accounts/secrets with a strict `X-API-Env` allow-list, transparent refresh through server-side expiry, scrubbed session echo, vendor 404 normalised to `problem+json` (with a per-route opt-out) | Nothing (in-process CRM stub) | `-- --smoke` (in-process) |

The library ships **no built-in vendor presets** (0.4.0): every vendor above is one
isolated sample whose full setup is plain config. A community preset
(`CredProx:Presets` or a custom `IPresetSource`) can package a sample's fixed facts for
reuse — see the Spotify README.

## Before you build: pack the packages

Examples consume CredProx **as NuGet packages** (plan §6 quality bar — this is what catches
packaging mistakes), restored from the local feed `artifacts/packages` via
`samples/nuget.config`:

```bash
dotnet pack src/CredProx.Abstractions -c Release -o artifacts/packages
dotnet pack src/CredProx -c Release -o artifacts/packages
dotnet pack src/CredProx.AzureKeyVault -c Release -o artifacts/packages
dotnet pack src/CredProx.Testing -c Release -o artifacts/packages
```

(Or just run the CI `examples` job's first step. Once a version is published to a real
feed, `samples/nuget.config` drops the local source.)

## No real secrets, ever

Examples read secrets from environment variables or user-secrets and fail at startup naming
the exact missing value. Demo values that do appear (E1's static key, E2's container-local
Keycloak client, E6's WireMock stubs) are throwaway and only ever talk to local stubs.
