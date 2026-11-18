# Extending CredProx

Everything the built-in credential types, authenticators and secret sources use is
public. A third-party package is written the same way ours are: implement a contract
from `CredProx.Abstractions`, expose one `AddCredProx…` registration call, and prove
the behavior with the conformance suites in `CredProx.Testing`. The smallest complete
example is [`samples/CustomPlugin`](../samples/CustomPlugin) — a credential type in
~50 lines plus its conformance cells.

## The seams

| Seam | Contract | You register with |
|---|---|---|
| Caller authenticator | `ICallerAuthenticator` | `AddCredProxCallerAuthenticator<T>()` — registering one brings the caller policy pipeline with it |
| Registry validator | `ICallerRegistryValidator` | `AddCredProxCallerRegistryValidator<T>()` — a fail-closed startup check over the built caller registry |
| Registry contributor | `ICallerRegistryContributor` | register your implementation; the core builds the registry from all contributors, generation-tracked |
| Credential type | `ICredentialProvider<TOptions>` | `AddCredProxCredentialType<TProvider, TOptions>(typeName)` |
| Secret source | `ISecretSource` (+ `ISecretAccessor` for resolution) | register the source; `secret:` references then resolve through it, unresolvable names refuse startup |
| Pipeline feature | `IPipelineFeature` (plus the request / connection / response flavours) | register the feature; stages run in a fixed order, and `AbortAsync` short-circuits the pipeline |
| Body hand-off | `CredProxRequestState` | read-only: features that need the whole outbound body buffer through this measured seam, with a byte cap |

## The rules that make a package first-class

- **No `InternalsVisibleTo`.** The built-in packages open their internals only to their
  own test assemblies. An extension package must compile against the public surface
  alone — if something you need is internal, that is an API gap worth an issue.
- **Unregistered names are refused at startup, never ignored.** A credential section
  naming a `Type` nobody registered fails startup, and there is no discovery scan and
  no default fallback. Your package must call its registration explicitly; the error
  names the missing type so the host author knows what to reference.
- **One registration call, plain config.** Follow the built-ins: an extension method on
  `IServiceCollection`, an options class bound from a config section, and a validator so
  bad config refuses startup with a precise message instead of failing the first
  request. Ship a `README.md` that names the call and the config keys.
- **Secret values never leave the accessor.** Resolve through `ISecretAccessor` per use;
  never store a secret in a long-lived field, log one, or place one in an error message.
  `CredProx.Testing`'s `CapturedLogSink.AssertNoSecretValues` proves it.
- **Prove behavior, not just compilation.** Derive your tests from the conformance
  suites (`CredentialProviderConformanceTests`, `SecretSourceConformanceTests`,
  `TokenCacheConformanceTests`): refresh-on-401, single-flight, cache scoping and secret
  hygiene are checked the same way for plugins as for built-ins.
- **Mark what is still moving.** New public API that may change before 1.0 carries
  `[Experimental("CREDPROX001")]`, the same stamp the core's plugin-facing surfaces use.

## Where to look next

- [`src/CredProx/README.md`](../src/CredProx/README.md) — the package map and the seam
  list beside the core's own registration calls.
- [`samples/CustomPlugin`](../samples/CustomPlugin) — the template end to end.
- [`docs/vendors/`](vendors/) — how vendor integrations look as pure config; a preset
  under `CredProx:Presets` (or a custom `IPresetSource`) can package those facts.
