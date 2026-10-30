# Security self-review — 0.3.0 release (M11)

Builder's pass over CredProx's security boundaries for the first public release, per
plan §9. Each boundary: the promise, where it is implemented, what pins it, and what
residual risk remains. The independent adversarial pass (dev-review) is recorded on the
M11 queue row; this document is the input to it, not a substitute.

Test-project shorthand: **UT** = `tests/CredProx.Tests`, **ST** =
`tests/CredProx.SecurityTests`, **CT** = `tests/CredProx.ConformanceTests`, **E2E** =
`tests/CredProx.E2ETests`.

## 1. Secret scoping

**Promise.** A credential can resolve only the `secret:` references its own configuration
declares; one credential never reads another's secrets; a preset cannot introduce a
secret reference the host did not configure.

**Implementation.** `src/CredProx/Secrets/ScopedSecretAccessor.cs` (per-credential
accessor built from the declaration set), `SecretAccessorFactory.cs`,
`SecretReferenceValidator.cs` (startup resolution), `Presets/PresetConfiguration.cs`
(preset-introduced references validated through the host's sources — the startup scan
composes presets before validating, `Startup/CredProxStartupValidator.cs`).

**Pinned by.** UT secret-scoping and validator suites; ST `SecretLeakProperties`; UT
`CredProxStartupValidatorTests` including the preset-introduced-secret cases (M10 F1 —
mutation-probed: removing the preset composition from the startup scan fails the test);
CT `SecretSourceConformanceTests`.

**Residual.** A fully-dynamic declaration (`secret:{partition}`) admits every name by
design — startup warns, the operator narrows. Deliberate (§3.2).

## 2. Secret non-leakage

**Promise.** Secret values never appear in logs, error/problem responses, audit records,
or exception text — only names and references.

**Implementation.** Problem responses (`Yarp/CredProxProblemResponses.cs`) carry codes
and credential **names**; audit masking (`Audit/AuditRedactor.cs`) masks configured
headers and nested JSON fields before any sink; `SecretValues.cs` keeps values out of
binding/debug surfaces; log call sites pass names.

**Pinned by.** ST `SecretLeakProperties` (FsCheck: random values, generated contexts,
assert absence across all output surfaces), ST `AuditRedactionProperties`,
`CapturedLogSink.AssertNoSecretValues` in CT and every sample smoke, E2E checks.

**Residual.** Host-configured logging outside CredProx (e.g. a host logging
`IConfiguration` wholesale) is the host's surface, not ours. Third-party library logs
(YARP, Polly) are checked in smokes but not property-tested.

## 3. Caller authentication and least privilege

**Promise.** Unknown/absent caller key → `401`, no upstream request; keys compared in
constant time; operation allow-lists fail closed (no matching rule → `403`).

**Implementation.** `Callers/ConfigCallerStore.cs` (`CryptographicOperations.
FixedTimeEquals` over SHA-256 hashes), `CallerKeyAuthenticationHandler.cs`,
`OperationAllowListFeature.cs`, `PathPatterns.cs`.

**Pinned by.** ST `CallerAllowListProperties` (fail-closed under generated requests), UT
caller suites, E2E, sample E7 smoke (401/403/200 paths with audit records).

**Residual.** Caller keys are stored as **unsalted SHA-256 hashes** — a lookup index,
not a password store: low-entropy keys are crackable offline if the registry leaks.
Documented in README/SECURITY as an operator requirement (128+ bit CSPRNG keys). Key
rotation is config-level (add, retire).

## 4. Destination allow-lists

**Promise.** A templated destination cannot be steered outside its declared allow-list —
including via percent-encoding, case tricks, or path/host normalization surprises.

**Implementation.** `Destinations/PartitionSourceBinding.cs` (admission before
expansion), `DestinationRegistry.cs` (`ResolvePrefix` runs only on admitted values),
`DestinationBinder.cs` (a `{partition}` template without an allow-list fails startup).

**Pinned by.** ST `PartitionAllowListProperties` (adversarial partition strings), UT
binder/registry suites, E2E, sample E6 smoke (blocked partition).

**Residual.** Kestrel vs TestServer decoding differences are documented in project
memory and covered by tests (`%2F` survives Kestrel decoding, `%2e` normalizes) — but a
fronting proxy that re-decodes differently is deployment surface.

## 5. Header hygiene

**Promise.** Inbound `Authorization` and caller keys never reach the upstream; injected
credential headers replace, never duplicate; response-side headers carry no secrets.

**Implementation.** `Features/CredentialAttachFeature.cs` (remove-then-add attachment),
`Yarp/CredProxRequestState.cs` (inbound header capture for audit is redacted), request
pipeline in `Yarp/CredProxForwarderHttpClientFactory.cs`.

**Pinned by.** ST `HeaderHygieneProperties`, UT feature suites, sample smokes that echo
upstream headers (E1, E6, E10).

**Residual.** Vendor-chosen header names outside the configured set pass through — by
design; the allow-list of what is *injected* is the credential config itself.

## 6. Token cache isolation

**Promise.** Cache entries are keyed per (credential, partition); one partition never
receives another's token; negative results are cached briefly and scoped.

**Implementation.** `TokenCaching/InMemoryTokenCache.cs` (key = credential + partition;
single-flight gate per key; `NegativeCacheTtl`; early refresh).

**Pinned by.** UT cache suites, CT `TokenCacheConformanceTests`, E2E (revocation +
burst), benchmarks pin the hot paths' shape (`tests/CredProx.Benchmarks`).

**Residual.** In-process only: multi-instance deployments each hold their own cache
(`ITokenCache` is the extension point for a distributed backing — not built in 0.3).

## 7. Signing credential types (M9)

**Promise.** `JwtAssertion` signs the client assertion with the configured key without
logging it; `Hmac` signs the configured canonical string; body buffering is bounded
(size cap → `413`).

**Implementation.** `Credentials/JwtAssertionProvider.cs`, `HmacProvider.cs`,
`HmacSigner.cs`, `HmacOptions.cs` (canonical-string shape, buffering limits).

**Pinned by.** UT signing suites (known-answer vectors), ST leak checks over the
signing paths, sample E8 (JWT verified by stub) and E9 (signature verified, cap
answers 413) smokes.

**Residual.** Key *storage* is the host's choice (PEM via `secret:` reference, or Key
Vault); a host that inlines a key in plain config owns that risk.

## 8. Fail-closed configuration

**Promise.** Bad configuration fails startup (one collected report of names, never
values); a bad reload is refused and the previous configuration keeps serving.

**Implementation.** `Startup/CredProxStartupValidator.cs`, `CredProxConfigValidator.cs`
(reload-time cross-checks), registry providers rebind on change tokens.

**Pinned by.** UT validator/binder suites, config-reload tests (M5 story), E2E reload
cases.

**Residual.** None blocking; startup validation is the design's backbone and is
mutation-probed (M10 F1).

## 9. Release-surface checks (M11)

- **No committed secrets.** `git grep` for AWS/GitHub/SSH-key/JWT shapes over tracked
  files: clean. Samples use placeholders, user-secrets or env vars and fail with a
  message naming the missing value (§6 quality bar).
- **Package contents.** 0.3.0 packs verified: README, Gitea `repository`/`projectUrl`
  metadata, SourceLink in the snupkg PDB pointing at
  `http://10.10.1.5:3300/hxr/cred-prox/raw/commit/<sha>/*`, symbols, deterministic
  build, `EnablePackageValidation`.
- **Publish from CI, or pack with CI path mapping.** Plain local packs embed the
  builder's source root (`/home/...`) in the PDB; CI's `ContinuousIntegrationBuild`
  maps it to `/_/`. Publish the CI artifact, or pack locally with
  `-p:ContinuousIntegrationBuild=true` — the runbook ([`/PUBLISHING.md`](../PUBLISHING.md))
  states the steps and the pre-push symbol assertion.
- **Gitea web reachability.** During M11 the repo carried the wrong port (`:3000`), which
  refused connections; the person confirmed the correct instance URL
  (`http://10.10.1.5:3300`) on 2026-10-16 and it answers from the dev machine. All baked
  URLs now carry `:3300`; it must stay reachable at publish time or SourceLink and
  package links point at a closed port.
- **Dependencies.** YARP 2.3.0, `Microsoft.Extensions.*` 9.0.x, Azure SDKs — no known
  open CVEs against these versions at review time; `dotnet list package --vulnerable`
  runs in CI.
- **Transport.** CredProx terminates no inbound TLS itself beyond the host's Kestrel
  config; outbound is `https` by default and `http` only where a sample's local stub
  needs it. Not a library-enforced boundary — documented deployment surface.

## Known limitations (accepted for 0.3.0)

1. In-process token cache only (§6 residual).
2. Unsalted caller-key hashing — operator entropy requirement (§3 residual).
3. `[Experimental]` API surface may still change before 1.0 (announced, not silent).
4. Audit sinks ship as in-memory/log sinks; durable sinks (DB/queue) are plugin work.
5. Single-instance rate limiting and circuit state (per-process).
