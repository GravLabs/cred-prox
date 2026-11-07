# E8 — GitHub App installation tokens

The `JwtAssertion` credential minting a GitHub App JWT and exchanging it for an
installation token (plan §6 E8). No vendor-specific code and no presets: the generic
JwtAssertion type in `BearerExchange` mode is exactly GitHub's flow, spelled out in full
in `appsettings.json`.

## What it shows

- The whole GitHub shape is plain config: RS256, `Audience` = `https://api.github.com`,
  9-minute `Lifetime`, `Exchange: BearerExchange` (the JWT goes out as
  `Authorization: Bearer <jwt>`), and the response mapping GitHub needs —
  `TokenField: token`, `ExpiresAtField: expires_at` (absolute expiry, no `expires_in`) —
  plus the App's own two values: `Issuer` (the App id) and `TokenEndpoint` (the
  installation's endpoint).
- The exchanged installation token is cached per credential+partition until
  `expires_at`; the app JWT is minted fresh at each exchange, never cached.
- The route attaches the cached installation token to every forwarded request at
  `Stage.AttachCredential` (`Authorization: Bearer ghs_…`).

## Run the smoke (CI, no Docker, no GitHub account)

```bash
dotnet run -- --smoke
```

A generated RSA key stands in for the App private key, and both GitHub endpoints are
stubbed in-process. The token-endpoint stub verifies the app JWT with an independent
implementation — RS256 signature against the generated public key plus `iss`/`aud`/`exp`/
`jti` checks — then returns a fake installation token. The smoke asserts the proxied
GitHub call carries `Bearer ghs_stub_installation`.

## Point it at a real GitHub App

1. Create a GitHub App, note its **App ID**, generate a **private key** (PEM), and
   install the App on the org/repos you want to reach (note the **installation ID**).
2. Put the PEM into your secret source under the name the credential references
   (`secret:github-app-signing-key` reads `CredProx:Secrets:github-app-signing-key`; an
   environment variable or file secret source works the same way).
3. Set `Issuer` to the App ID and `TokenEndpoint` to
   `https://api.github.com/app/installations/<installation-id>/access_tokens`.
4. Call `GET /github/repos/<owner>/<repo>` through the proxy — GitHub answers as the
   App installation.
