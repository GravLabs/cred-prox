# ADR-0007: Six packages, grouped by dependency, and one entry point

Status: Accepted (owner decision 2026-11-20; to be built in M49 for 0.15.0). It replaces the
package list in ADR-0005 decision 2; ADR-0005's other decisions stand.
Date: 2026-11-20

## Context

ADR-0005 split every optional feature into its own package so that a host carries only the
outside libraries it uses. That produced ten packages at 0.12.0. Measured at 0.14.0, three of
them add no outside library at all, and two share one dependency tree:

| Package | Lines | Outside libraries (beyond ASP.NET Core) |
|---|---|---|
| `CredProx` | 12,617 | YARP |
| `CredProx.CallerKeys` | 699 | none |
| `CredProx.Hmac` | 751 | none |
| `CredProx.LoginExchange` | 575 | none |
| `CredProx.OAuth` | 2,445 | the Microsoft identity libraries (`Microsoft.IdentityModel.*`) |
| `CredProx.CallerTokens` | 955 | the same identity libraries plus the JWT bearer handler |
| `CredProx.Operations` | 1,568 | Polly and the Microsoft resilience packages |
| `CredProx.AzureKeyVault` | 155 | Azure.Core |
| `CredProx.Abstractions` | 1,065 | none |
| `CredProx.Testing` | 817 | xunit |

A host also has to know which feature needs a setup call, and passes its configuration twice
(`services.AddCredProx(configuration)` and the reverse-proxy builder's
`AddCredProx(configuration)`). There are 20 public `AddCredProx…` methods, most of them
internal wiring. There are no consumers yet (owner, 2026-11-20), so the contract can change in
whatever way is cleanest for consumers.

## Decision

1. **Six packages, grouped by the outside libraries they bring in:**
   - `CredProx`: the core, now including caller API keys, HMAC signing and login exchange;
   - `CredProx.Identity`: OAuth client credentials, token exchange, JWT assertion, and caller
     (agent) tokens;
   - `CredProx.Azure`: the `TokenCredential` credential type, renamed from
     `CredProx.AzureKeyVault`, which never held Key Vault code (a host reads Key Vault through
     the Azure SDK's own configuration provider);
   - `CredProx.Operations`, `CredProx.Abstractions`, `CredProx.Testing`: unchanged in scope.
   A host still gets only the outside libraries it uses. A package may depend on the core and
   the abstractions, never on another feature package (ADR-0005).
2. **A feature inside the core works from configuration alone**, as `StaticKey` does today:
   `Type: Hmac`, `Type: LoginExchange`, callers with key hashes and a `CredProx:Audit` section
   need no setup call. A feature in another package is enabled by that package's one setup
   call, and inside that package each feature is switched on by its own configuration.
3. **No unused machinery.** A host whose configuration declares no callers registers no
   authentication scheme and no authorization policy, exactly as `QuickStart` behaves at
   0.14.0. Caller-key authentication is registered only when callers with key hashes are
   configured, and caller-token authentication only when caller tokens are configured, so an
   OAuth-only host registers no authentication scheme either.
4. **Fail closed stays.** A configured caller with no way to authenticate (no key hash and no
   caller-token setup) refuses startup, naming the caller. A credential `Type` whose package
   is not set up refuses startup, naming the type and the package to add.
5. **One entry point.** The host passes its configuration once.
   `services.AddCredProx(configuration)` returns a builder, and each add-on package adds one
   chained call to it: `.AddIdentity()`, `.AddOperations()`, `.AddAzure(credential)`. The
   reverse-proxy builder's `AddCredProx()` takes no configuration and refuses, by name, to run
   before the services entry. Plugin authors extend the builder (`WithCredentialType`,
   `WithCallerAuthenticator`, `WithCallerRegistryValidator`, `WithCallerRegistryContributor`).
6. **Namespaces.** Every type a host uses lives in `CredProx`; every extension point a plugin
   author implements lives in `CredProx.Abstractions` (including `ICallerStore` and
   `CallerKeyMatch`); `CredProx.Testing` keeps its own. Setup extension methods stay in
   `Microsoft.Extensions.DependencyInjection`.
7. **Only the setup methods a host or plugin author needs stay public.** Each of the 20
   current `AddCredProx…` methods is kept, folded into the builder, or made internal, and the
   list is recorded in the CHANGELOG.

## Consequences

- Hosts write less setup code, and the package choice follows one rule: install a package only
  for the outside library it brings.
- The core grows by about 2,000 lines and gains no outside library.
- Everything above is a breaking change, shipped as 0.15.0 before the 1.0 freeze. The CHANGELOG
  gives the package map and the before/after setup code. The five retired packages
  (`CallerKeys`, `Hmac`, `LoginExchange`, `OAuth`, `CallerTokens`) and the renamed
  `AzureKeyVault` get no new versions. Owner decision 2026-11-21 ("remove any published packages
  that are no longer used"): every published version of those six ids, 40 in all, was deleted
  from the package registry before 0.15.0 shipped; `CredProx`, `CredProx.Abstractions`,
  `CredProx.Operations` and `CredProx.Testing` keep all their earlier versions.
- APICompat: the three unchanged packages and the core validate against the published 0.14.0
  bytes with one named suppression per intended break; `CredProx.Identity` and
  `CredProx.Azure` ship first at 0.15.0 with no baseline (ADR-0001).

## Rejected options

- **Seven packages** (the identity packages kept apart): an OAuth-only host would avoid only
  the small JWT bearer handler, at the cost of one more package to choose.
- **Grouping by job** (all credential types, all caller checks): a key-only caller host would
  carry the JWT libraries.
- **One package for everything optional**: every host carries every outside library again.
- **A meta-package that references the others**: adds a package instead of removing them.
