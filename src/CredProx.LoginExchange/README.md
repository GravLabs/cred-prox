# CredProx.LoginExchange

Vendor-login credential add-on for [CredProx](https://github.com/GravLabs/cred-prox):

- **The `LoginExchange` credential type** — for vendors with no OAuth at all: POST a
  per-environment service account and password to the login endpoint, get a session
  token back, and forward it as `Authorization: <Scheme> <token>`.
- **One credential, many environments** — the login URL, account and password are
  templates expanded through the core's shared `{partition}`/`secret:` expander, and the
  `Partition` allow-list admits the environments a credential may serve while anything
  else is refused at startup.
- **Cached per `(credential, partition)`** by the core token cache — early refresh,
  single-flight and negative caching included.
- **Failure-safe** — the password must be a `secret:` reference (never a literal in
  configuration), and a refused login names neither secret values nor response bodies;
  the raw session token never enters a log or an exception.

## Setup

```csharp
builder.Services.AddCredProx(builder.Configuration); // core defaults, one call
builder.Services.AddCredProxLoginExchange();
```

Configuration keeps `Type: LoginExchange` unchanged (see the
[`LoginExchange` sample](https://github.com/GravLabs/cred-prox/tree/main/samples/LoginExchange),
whose WireMock mappings stand in for the vendor). A credential naming
`Type: LoginExchange` without this package fails startup naming the package to add.

## License

MIT
