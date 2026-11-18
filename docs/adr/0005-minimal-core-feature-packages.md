# ADR-0005: A minimal core; every optional feature is its own package

Status: Accepted (owner decision 2026-11-16; to be built in M42)
Date: 2026-11-16

## Context

Every feature so far has been added to the `CredProx` package. At 0.11.0 it holds 16,258 lines
of C#. That includes all six vendor credential types, caller keys and caller tokens,
throttling, budgets, resilience and health probes. It also pulls in the JWT bearer and OpenID
Connect libraries for every host, even a host that uses neither.

The extension seams mostly exist already: `CredProx.Abstractions` defines `ICredentialProvider`,
`IPipelineFeature`, `ICallerStore`, `ISecretSource` and `IAuditSink`, and sample E10 proves that
a separate package can add a credential type. The one missing seam is caller authentication:
the caller-authentication stage knows API keys and caller tokens directly. That is why
M39's caller tokens (ADR-0004) went into the core.

The examples have the same problem. A sample's `Program.cs` mixes the production host with its
own test harness (E19 is 217 lines, about 20 of which are the host). A reader cannot copy one
as a production starting point.

## Decision

1. **The core is the security floor and the contracts, nothing else.** `CredProx` keeps:
   - the YARP integration and the pipeline stages;
   - the destination allow-list, header hygiene and response scrubbing;
   - audit and the kill switch;
   - the caller identity and the operation allow-list;
   - secrets (`ISecretSource`, configuration secrets);
   - fail-closed startup validation;
   - the static-key credential, the base case.
   
   `CredProx.Abstractions` keeps the contracts.
2. **Each optional feature is its own package** and registers only through public seams, the
   same ones a third party would use:
   - `CredProx.OAuth`: client credentials, token exchange, JWT assertion. (Revised in M42
     slice 4: the in-memory token cache stays in the core, because the core credential binder
     caches through it for every credential type and other packages use `ITokenCache`.);
   - `CredProx.Hmac`;
   - `CredProx.LoginExchange`;
   - `CredProx.CallerKeys`: caller API keys;
   - `CredProx.CallerTokens`: OIDC/Entra agent tokens (ADR-0004);
   - `CredProx.Operations`: throttling, budgets, resilience, health probes. (Revised in M42
     slice 4b: the shipped package holds the throttle, the resilience adapter and the health
     probes; caller budgets and the kill switch stay core policy, sharing the core
     `FixedWindowRateLimiter` with the throttle.);
   - `CredProx.AzureKeyVault` and `CredProx.Testing` stay as they are.
   
   A package may depend on the core and the abstractions, never on another feature package.
   If a feature package needs `InternalsVisibleTo` or an internal type, the seam is missing,
   and the fix is a public seam.
3. **One new seam: caller authentication.**
   - The core's caller stage asks the registered caller authenticators for a `CallerIdentity`.
   - The core still owns the operation allow-list and the scope intersection: an authenticator
     reports identity and scopes; it never decides what is admitted.
   - With no caller authenticator registered, the host refuses to start (fail closed), unless
     the configuration declares no callers at all, as today.
   - ADR-0004's guarantees move with `CredProx.CallerTokens` unchanged:
     - the strict named-rule rule;
     - `MaxTokenAge` enforced before any claim mapping, so a swapped mapper cannot drop it;
     - the bearer token stripped before forwarding.
4. **The core sheds its identity and resilience dependencies.** JWT bearer, OpenID Connect and
   the HTTP resilience packages move to the feature packages that use them.
5. **Examples are production-shaped.** Each sample is the host a user would deploy:
   - a short `Program.cs` that registers only the packages it uses, plus `appsettings.json`;
   - no test harness and no demo-only switches in `Program.cs` (an offline stub's settings
     live in an environment-specific config file);
   - each sample's smoke check moves to a test project that drives the sample from outside.
6. **Contract breaks are accepted** (owner, 2026-11-15/16: no consumers yet). The split ships as
   one minor release, and the CHANGELOG gives the package-to-feature map and the one-line
   migration for each feature.

## Consequences

- A host that only attaches a static key installs the core alone, with no JWT or OAuth code.
- Every built-in feature becomes a working proof of the public seams. A feature that cannot be
  built outside the core shows a gap in the extension model, and is fixed there.
- More packages to version and publish. They are released together under one version, and
  APICompat runs per package. The baseline rotation starts fresh for the new packages
  (ADR-0001).
- Tests move with their code. Coverage gates apply per package.

## Rejected options

- **Two add-on packages** (all credentials, all callers): fewer packages, but a host still
  carries every credential type's dependencies, and the core keeps throttling and health.
- **One "extras" package**: the smallest package count, but every non-core dependency ships
  together.
- **Keep the monolith, document the seams**: it does not shrink what every host carries, and
  it leaves the caller-authentication seam missing.
