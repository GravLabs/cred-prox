# CredProx.Testing

The test toolkit for [CredProx](https://github.com/GravLabs/cred-prox) plugin authors: the
same fakes and conformance suites the built-in credential types, secret sources and the
token cache are tested with — so a plugin can prove it behaves like the built-ins on the
points that matter: secret hygiene, refresh-on-401, single-flight, cache scoping.

## Fakes

| Helper | What it does |
|---|---|
| `FakeUpstream` | an `HttpMessageHandler` standing in for the vendor API: scripted responses (`Enqueue`), a catch-all `Responder`, request recording, `Reset` |
| `FakeTokenServer` | the same for a vendor token endpoint: hands out fresh `tok-N` tokens, records request bodies |
| `CapturedLogSink` | an `ILoggerProvider` capturing log lines, with `AssertNoSecretValues(...)` — fails if any secret value ever reached the logs |

## Conformance suites

Derive from them and implement the abstract pieces; each suite runs the contract's
promises against your implementation:

- `CredentialProviderConformanceTests` / `CachingCredentialProviderConformanceTests` —
  provider behaviour including refresh and failure paths
- `SecretSourceConformanceTests` — scoping and resolution rules
- `TokenCacheConformanceTests` — keying, single-flight, expiry semantics

## Example

[`samples/CustomPlugin`](https://github.com/GravLabs/cred-prox/tree/main/samples/CustomPlugin)
shows a ~50-line credential type conformance-tested with this package — the template for
community plugins.

## License

MIT
