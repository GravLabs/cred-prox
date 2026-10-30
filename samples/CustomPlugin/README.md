# E10 — CustomPlugin: writing a credential-type plugin

The template for community plugins (plan §6 E10): a credential type CredProx does not
ship — `VendorSession`, the legacy-vendor shape of *POST appId+secret as JSON, get a
session id back, send it as a custom header* — in about fifty lines, registered
explicitly, and tested with the same `CredProx.Testing` conformance suites the built-ins
run. No vendor account, no Docker.

## The three pieces

**1. The provider** ([VendorSessionProvider.cs](VendorSessionProvider.cs)) — options +
provider. The options implement `IHasAttachment` to say where the value goes (header
`X-Session-Id`, raw); the provider takes `ITokenCache`, `IHttpClientFactory` and
`TimeProvider` from DI, resolves its own `secret:` references through the **scoped**
`ISecretAccessor` (it can only read this credential's secrets — plan §3.5 rule 4), and
caches through `ITokenCache` — which is what buys single-flight, per-partition isolation
and refresh-on-401 for free. Failure messages name the status, never a body or a secret.

**2. The registration** ([Program.cs](Program.cs)) — one explicit line:

```csharp
builder.Services.AddCredProxCredentialType<VendorSessionProvider, VendorSessionOptions>("VendorSession");
```

(plus `AddHttpClient()`, since the provider takes `IHttpClientFactory` from DI — hosts
that also register the built-ins get that already.)

The binder, startup validation, secret scoping, cache and attach step then treat the
plugin exactly like a built-in; the config is a normal credential section with
`"Type": "VendorSession"`.

**3. The conformance suite** ([VendorSessionConformanceTests.cs](VendorSessionConformanceTests.cs)) —
inherit `CachingCredentialProviderConformanceTests<TProvider, TOptions>`, describe the
credential in configuration, list the secret values, done. You get: acquire succeeds with
the configured inputs; 100 concurrent acquires collapse to **one** token call;
invalidate-then-acquire yields a fresh token; a failure under one partition doesn't
poison another; no secret value ever appears in a log line; a failed acquire leaks nothing.

## Run it

```bash
./smoke.sh
```

which runs both halves:

```bash
dotnet run -- --selftest   # the conformance facts, driven without a test runner
dotnet run -- --smoke      # proxy path: in-process login + echo stubs
```

`--selftest` prints a PASS line per fact — in your own plugin project the same facts are
plain xunit `[Fact]`s and `dotnet test` runs them. `--smoke` proxies two requests with no
credential in them; the vendor stub sees `X-Session-Id: vsess_stub_1` on both and counted
exactly **one** login — the plugin's cache did the collapsing.

## What a plugin does *not* have to do

Nothing about logging hygiene, cache keying, secret plumbing or 401 retry is yours to
reimplement — the suite's point (§5.2) is that those are core behaviors your provider
inherits, and the suite proves it does. The built-ins run the identical suites in
`tests/CredProx.ConformanceTests`; there is no privileged path.
