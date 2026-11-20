# CredProx.CallerKeys

Caller-API-key add-on for [CredProx](https://github.com/GravLabs/cred-prox):

- **Validated caller keys** — callers present an API key under the caller-key
  scheme; presented values are hashed with SHA-256 and compared in constant time
  against the configured `sha256:<hex>` hashes (which may live behind a
  `secret:` reference). Unknown, expired and revoked keys fail identically, and
  the key value never enters a log, a claim or an exception (ADR-0005).
- **Key rules enforced where the registry lives** — the core runs this package's
  entry-shape rules at host start AND on every live configuration rebind: a key
  without `KeyId` or `KeyHash`, a duplicated `KeyId`, an unparseable `ExpiresAt`
  or a `sha256:` hash that is not 64 hex digits is refused. A refused live edit
  never takes effect — the previous registry keeps serving and the reason is
  logged.
- **Key rotation and revocation without a restart** — the live registry rebinds
  on configuration changes; the store follows it.
- **A replaceable store** — key lookup is the `ICallerStore` interface, a public
  seam that ships in this package's `CredProx.CallerKeys` namespace: register your
  own implementation (database, identity provider) before
  `AddCredProxCallerAuthentication` to decide caller identity from somewhere other
  than configuration.

## Setup

```csharp
builder.Services.AddCredProxCallerAuthentication(builder.Configuration);
```

Configure the inbound header under `CredProx:CallerAuth` (default
`X-CredProx-Key`) and each caller's keys under `CredProx:Callers:<id>:Keys`
(see the [`CallerApiKey` sample](https://github.com/GravLabs/cred-prox/tree/main/samples/CallerApiKey)).
The core keeps the caller policy — the caller registry, operation allow-lists,
budgets and the kill switch — and reads no key values: a host that never
references this package ignores `Keys` entirely.

## Install

```bash
dotnet add package CredProx.CallerKeys
```

Installs beside `CredProx`; the core package README carries the package map.

## License

MIT
