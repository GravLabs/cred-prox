# Writing a credential-type plugin

## What it demonstrates

The template for community plugins: a credential type CredProx does not ship —
`VendorSession`, the legacy-vendor shape of *POST appId+secret as JSON, get a session id
back, send it as a custom header* — in about fifty lines, registered explicitly, and
tested with the same `CredProx.Testing` conformance suites the built-ins run. No vendor
account, no Docker: `StubApi/` is the legacy vendor the cells drive.

## The three pieces

**1. The provider** ([VendorSessionProvider.cs](VendorSessionProvider.cs)) — options +
provider. The options implement `IHasAttachment` to say where the value goes (header
`X-Session-Id`, raw); the provider takes `ITokenCache`, `IHttpClientFactory` and
`TimeProvider` from DI, resolves its own `secret:` references through the **scoped**
`ISecretAccessor` (it can only read this credential's secrets), and caches through
`ITokenCache` — which is what buys single-flight, per-partition isolation and
refresh-on-401 for free. Failure messages name the status, never a body or a secret.

**2. The registration** ([Program.cs](Program.cs)) — one chained seam call:

```csharp
builder.Services.AddCredProx(builder.Configuration)
    .WithCredentialType<VendorSessionProvider, VendorSessionOptions>("VendorSession");
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
poison another; no secret value ever appears in a log line; a failed acquire leaks
nothing.

## Run it

```bash
cd samples/CustomPlugin
export CredProx__Credentials__vendor-session__AppId=demo-app
export CredProx__Secrets__vendor-secret=demo-vendor-secret
export CredProx__Credentials__vendor-session__LoginEndpoint=http://localhost:8094/login
export CredProx__Destinations__vendor__Template=http://localhost:8094
export ReverseProxy__Clusters__vendor__Destinations__vendor__Address=http://localhost:8094/
(cd StubApi && dotnet run &)   # the vendor stand-in
dotnet run
```

Then call through the proxy with no credential of your own:

```bash
curl -s http://localhost:5090/vendor/echo
```

```
{"sessionId":"[redacted]"}
```

The vendor saw `X-Session-Id: <session id>` on the call; you see it redacted — the same
response scrubbing the built-ins get, because the pipeline treats your plugin's value
exactly like any injected credential.

## Point it at a real vendor

Swap the four endpoint/identity values above for the real login endpoint and account,
and keep the secret in your secret source (the empty `CredProx:Secrets:vendor-secret` in
`appsettings.json` is the placeholder the env var answers). The provider code does not
change — that is the plugin's whole contract.

## Verify it

```bash
cd samples/CustomPlugin && ./smoke.sh
# or directly:
dotnet test tests/CredProx.SampleSmokes --filter Sample=CustomPlugin
```

Five cells: the plugin-minted session id arrives at the vendor byte-exactly (the
stand-in's `/exact` witness), a reflecting JSON echo comes back redacted, two proxied
calls collapse to **one** vendor login (the core's caching serves the plugin), a wrong
secret gets the static credential problem with no value in any output line — and the
conformance suite the plugin ships runs here as a cell: the same facts `dotnet test`
runs in your own plugin project, driven through the real binder, secret scoping and
cache wiring.

## What a plugin does *not* have to do

Nothing about logging hygiene, cache keying, secret plumbing or 401 retry is yours to
reimplement — the suite's point is that those are core behaviours your provider
inherits, and the suite proves it does. The built-ins run the identical suites in
`tests/CredProx.ConformanceTests`; there is no privileged path.
