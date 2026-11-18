# GitHub App installation tokens, as configuration

## What it demonstrates

GitHub's whole authentication shape in explicit config — no vendor-specific C#, no
presets. The generic `JwtAssertion` credential in `BearerExchange` mode is exactly the
GitHub App flow:

- CredProx mints an **RS256 app JWT** (iss = the App id, aud = `api.github.com`, a fresh
  `jti` every time, 9-minute `Lifetime`) and presents it as `Authorization: Bearer` to
  the **installation-access-tokens** endpoint (`Exchange: BearerExchange`).
- The response mapping GitHub needs is config: `TokenField: token`,
  `ExpiresAtField: expires_at` (absolute expiry — there is no `expires_in`). The
  exchanged **installation token is cached** until `expires_at`; the app JWT is minted
  fresh at each exchange, never cached.
- Every forwarded request carries the cached installation token
  (`Authorization: Bearer ghs_…`), attached at `Stage.AttachCredential` for the route.

## What you need

Nothing for the offline check — `StubApi/` is a GitHub stand-in the cells run (it
verifies the app JWT with an independent implementation: RS256 signature against the
generated public key plus `iss`/`aud`/`exp`/`jti`, the same checks GitHub's verifier
makes). A real GitHub App for the live run.

## Run it

```bash
cd samples/GitHubApp
export CredProx__Secrets__github-app-signing-key="$(cat /path/to/github-app-private-key.pem)"
dotnet run
```

Then call through the proxy — GitHub answers as the App installation:

```bash
curl -s http://localhost:5081/github/repos/octocat/hello-world
```

With no credential in and one out, the caller sees the installation token **only as a
redaction marker** (the response scrubber): a reflecting upstream is scrubbed
caller-side. The raw token still verifiably reaches the vendor — the stand-in's
`/exact` endpoint answers `ok` only when the header that arrived is byte-exactly
`Bearer <installation token>`, and never echoes it.

## The exact config

```jsonc
"CredProx": {
  "Destinations": { "github": { "Template": "https://api.github.com" } },
  "Credentials": {
    "github-app": {
      "Type": "JwtAssertion",
      "Algorithm": "RS256",
      "SigningKey": "secret:github-app-signing-key", // the App's private key PEM
      "Audience": "https://api.github.com",
      "Lifetime": "00:09:00",
      "Exchange": "BearerExchange",   // the JWT rides as Authorization: Bearer
      "TokenField": "token",          // GitHub's response member names
      "ExpiresAtField": "expires_at",
      "Issuer": "<app-id>",
      "TokenEndpoint": "https://api.github.com/app/installations/<installation-id>/access_tokens"
    }
  },
  "Secrets": { "github-app-signing-key": "" }  // empty in the file; supply the PEM
}
// and on the route:  "Metadata": { "CredProx.Credential": "github-app" }
```

The committed `appsettings.json` is exactly this with placeholder `Issuer` /
installation id. The private key never lives in the file: the empty
`github-app-signing-key` is a placeholder for the env var (or any secret source) you
set above.

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

Until the key is set, the host starts but every request answers
`credprox.credential_unavailable` — a cell pins that refusal (and that no key or token
material leaks into the host's output). A key GitHub does not know is refused the same
way: the stand-in's 401 on the token exchange surfaces as the static credential problem,
never as the vendor's body.

## Verify it

```bash
cd samples/GitHubApp && ./smoke.sh
# or directly:
dotnet test tests/CredProx.SampleSmokes --filter Sample=GitHubApp
```

Five cells drive the real host against the stand-in: the exchanged installation token
arrives at the vendor byte-exactly, a reflecting JSON echo comes back redacted, the
token is cached across requests (one exchange for many calls), the keyless host answers
the credential problem without leaking values, and a foreign key is refused by the
stand-in exactly as the real vendor would refuse it.
