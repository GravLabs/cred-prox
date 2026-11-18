# CredProx.OAuth

OAuth credential add-on for [CredProx](https://github.com/GravLabs/cred-prox):

- **`OAuthClientCredentials`** — the client-credentials grant against a vendor token
  endpoint, with `ClientAuthentication: Basic` (default) or `RequestBody`; `Scope` and
  `Audience` ride the form as configured.
- **`TokenExchange`** — the RFC 8693 token exchange: the caller's inbound bearer token is
  validated first (Authority discovery, or explicit Issuer+JwksUri over https per
  [ADR-0003](https://github.com/GravLabs/cred-prox/blob/main/docs/adr/0003-token-exchange-require-https-metadata.md)),
  then exchanged for the vendor token. The mandatory `Audience` pins which tokens are
  exchangeable; the removed Entra OBO mode stays refused
  ([ADR-0002](https://github.com/GravLabs/cred-prox/blob/main/docs/adr/0002-remove-entra-obo.md)).
- **`JwtAssertion`** — a signed client assertion in the client-credentials grant: HS256
  with `SigningKey` or RS256 with `SigningCertificate`; the assertion is signed in-process
  and never logged.
- **The token-lifetime policy carries across unchanged** — every vendor-stated expiry
  (`expires_in`, `expires_at`) follows the same accept, cap and reject rules, with the
  24 h cap and the once-per-credential notices; tokens are cached per
  `(credential, partition)` through the core's shared token cache, with one in-flight
  vendor call per key.

## Setup

```csharp
builder.Services.AddCredProx(builder.Configuration); // core defaults, one call
builder.Services.AddCredProxOAuth();
```

Configuration is unchanged from the core era — credential sections under
`CredProx:Credentials` with `Type: OAuthClientCredentials`, `TokenExchange` or
`JwtAssertion` (see the
[`OAuthKeycloak`](https://github.com/GravLabs/cred-prox/tree/main/samples/OAuthKeycloak),
[`TokenExchange`](https://github.com/GravLabs/cred-prox/tree/main/samples/TokenExchange)
and [`GitHubApp`](https://github.com/GravLabs/cred-prox/tree/main/samples/GitHubApp)
samples). A credential naming one of these types without this package fails startup
naming the package to add — the core keeps no type knowledge here beyond that hint.

## License

MIT
