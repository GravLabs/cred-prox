# CredProx.CallerTokens

Caller-token add-on for [CredProx](https://github.com/GravLabs/cred-prox):

- **Validated caller tokens** — the agent calling the proxy authenticates with an
  OIDC token (Entra or any issuer), and CredProx maps the validated principal to a
  configured caller by `TokenClientIds`. CredProx mints nothing: the issuer signs,
  the framework validates signature, issuer, audience and expiry (ADR-0004).
- **Client-id rules enforced where the registry lives** — the core runs this
  package's entry-shape rules at host start AND on every live configuration
  rebind: an empty or padded `TokenClientIds` entry admits nobody (entries match
  verbatim), and one client id listed by two callers is refused rather than
  decided by registry order. A refused live edit never takes effect — the
  previous registry keeps serving and the reason is logged.
- **Swap point** — register your own handler under the caller-token scheme
  (Microsoft.Identity.Web, another OIDC issuer, introspection) with the
  `registerScheme` callback; the mapping layer and the configured `MaxTokenAge`
  bound are unchanged.

## Setup

```csharp
builder.Services.AddCredProxCallerTokenAuthentication(builder.Configuration);
```

Configure the issuer and audience under `CredProx:CallerToken` and list each
caller's client ids under `CredProx:Callers:<id>:TokenClientIds` (see the
[`AgentTokens` sample](https://github.com/GravLabs/cred-prox/tree/main/samples/AgentTokens)).
A host that never references this package ignores `TokenClientIds` entirely — the
entries are inert and the key path is untouched.

## License

MIT
