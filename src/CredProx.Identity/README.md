# CredProx.Identity

Identity credential families for [CredProx](https://github.com/GravLabs/cred-prox), in
one package (ADR-0007) — you install it for the Microsoft identity libraries it brings:

- **Outbound credential types** — `OAuthClientCredentials`, `TokenExchange` and
  `JwtAssertion` with their options and validators (docs/adr/0002, docs/adr/0003 for the
  inbound-token rules; the M38 token-lifetime policy and the per-(credential, partition)
  cache ride the core's shared token cache).
- **Inbound caller (agent) tokens** — agents present short-lived OIDC access tokens
  instead of stored secrets; the stock JWT bearer handler validates them under the
  caller-token scheme, Entra app roles narrow the caller to its named operation rules,
  and `MaxTokenAge` caps token age from `iat` (ADR-0004). The scheme registers only when
  caller tokens are configured — an OAuth-only host registers no authentication scheme.

## Setup

```csharp
// Configuration once, then this package's one chained call:
builder.Services.AddCredProx(builder.Configuration)
    .AddIdentity();
```

A host that registers its own handler under the caller-token scheme passes the swap
delegate: `.AddIdentity(registerScheme: builder => ...)`.

Credential entries use `Type: OAuthClientCredentials`, `Type: TokenExchange` or
`Type: JwtAssertion` under `CredProx:Credentials`, plus `CredProx:TokenEndpoint` and
`CredProx:Connections`; caller tokens configure under `CredProx:CallerAuth`. See the
[`GitHubApp`](https://github.com/GravLabs/cred-prox/tree/main/samples/GitHubApp),
[`TokenExchange`](https://github.com/GravLabs/cred-prox/tree/main/samples/TokenExchange)
and [`AgentTokens`](https://github.com/GravLabs/cred-prox/tree/main/samples/AgentTokens)
samples.

## Install

```bash
dotnet add package CredProx.Identity
```

Installs beside `CredProx`; the core package README carries the package map.

## License
MIT
