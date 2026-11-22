# Extending CredProx

Everything the built-in credential types, authenticators and secret sources use is
public. A third-party package is written the same way ours are: implement a contract
from `CredProx.Abstractions` (except the caller-registry contributor contract, which
lives in the core), chain one extension method on the `CredProxBuilder` the
entry hands back (exactly as `.AddIdentity()` and `.AddOperations()` do), and prove
the behavior with the conformance suites in `CredProx.Testing`. The smallest complete
example is [`samples/CustomPlugin`](../samples/CustomPlugin) — a credential type in
~50 lines plus its conformance cells.

## The seams

| Seam | Contract | You register with |
|---|---|---|
| Caller authenticator | `ICallerAuthenticator` | `WithCallerAuthenticator<T>()` on the builder — registering one brings the caller policy pipeline with it |
| Registry validator | `ICallerRegistryValidator` | `WithCallerRegistryValidator<T>()` — a fail-closed startup check over the built caller registry |
| Registry contributor | `ICallerRegistryContributor` | `WithCallerRegistryContributor<T>()`; the core builds the registry from all contributors, generation-tracked |
| Credential type | `ICredentialProvider<TOptions>` | `WithCredentialType<TProvider, TOptions>(typeName)` |
| Secret source | `ISecretSource` (+ `ISecretAccessor` for resolution) | register the source; `secret:` references then resolve through it, unresolvable names refuse startup |
| Pipeline feature | `IPipelineFeature` (plus the request / connection / response flavours) | register the feature; stages run in a fixed order, and `AbortAsync` short-circuits the pipeline |
| Body hand-off | `CredProxRequestState` | read-only: features that need the whole outbound body buffer through this measured seam, with a byte cap |

## Replacing or turning off a built-in

The contract is in [ADR-0006](adr/0006-replace-or-turn-off-a-built-in.md): a single
service is replaced **host-first** — register your implementation before the
`AddCredProx` entry call and yours is the one used; a pipeline stage is **extend-only** —
you add a stage beside the built-ins, you do not replace or remove one, because the
stages are what lets CredProx promise a credential never reaches the upstream and a
secret never reaches the caller; and an optional stage is turned off **only by its
named switch**.

The single services, and how to replace each:

| Built-in | What it does | Replace how | Turn off |
|---|---|---|---|
| `ITokenCache` (in-memory) | Caches vendor tokens, one flight per key, early refresh | Register your `ITokenCache` before `AddCredProx` | No switch — the credential path needs a cache; replace it rather than remove it |
| `ISecretSource` (configuration-backed) | Resolves `secret:` references from `CredProx:Secrets` and reloads on config change | Register your `ISecretSource` before `AddCredProx` (your source owns its own reload) | No switch — it is the core's secret plumbing |
| `TimeProvider.System` | The clock everything time-based reads | Register your `TimeProvider` before `AddCredProx` (a test clock just works) | No switch |
| `ICallerStore` (caller keys) | Maps a presented caller key to its caller | Register your `ICallerStore` before `AddCredProx` | The caller-key feature is opt-in: without a key hash under `CredProx:Callers` there is nothing to turn off |
| `ICallerTokenMapper` | Turns an authenticated caller token into a caller | Register your mapper before `.AddIdentity()` | No switch — a caller token that maps to nobody is refused |
| The caller-token validation handler | Validates the caller token (issuer, audience, expiry) | Pass `registerScheme` to `.AddIdentity(registerScheme: …)` — your handler owns the scheme; the `MaxTokenAge` bound still applies | The caller-token feature is opt-in |
| The forwarder client factory | Builds the outbound `HttpClient` | Subclass `CredProxForwarderHttpClientFactory` and `Replace` it after the CredProx calls | No switch — outbound always goes through it |
| `IAuditSink` registrations | Where audit records go | Add your sinks; the recorder itself is not replaceable (that is deliberate) | `CredProx:Audit:Enabled=false` |

The pipeline stages — header hygiene, credential attach, operation allow-list,
scrubbing, error normalisation, the kill switch, refresh-on-401, the startup guards —
are **extend-only**: register your feature and it runs alongside them; removing a
built-in stage's registration is unsupported. Only these have an off switch:

| Switch | What it stops |
|---|---|
| `CredProx:Scrubbing:Enabled=false` | Response scrubbing |
| `CredProx:Errors:Enabled=false`; route metadata `CredProx.ErrorNormalisation="off"` | Error normalisation, globally or per route |
| `CredProx:Audit:Enabled=false` | Audit records |
| `CredProx:Health:Enabled=false` | Health monitoring entirely — neither the probe loop nor the `credprox` health check is registered |
| Route metadata `"CredProx.Caller": "anonymous"` | Caller authentication for that one route |

Everything else fail-closes and has no off switch by design: header hygiene strips,
credential attach, the operation allow-list, the kill switch, refresh-on-401, the
startup validators and the unknown-key refusal. If you genuinely need to replace a
stage, open an issue — the answer is an ADR discussion, not a hidden flag.

Four interactions worth knowing before you flip a switch:

- **Scrubbing off while error normalisation stays on:** the normaliser runs after the
  scrubber, so an error body's `vendor_detail` can embed vendor bytes that scrubbing
  would have removed. Turn both off, or keep scrubbing on.
- **A pre-registered `CallerKeyOptions`:** the caller-key extension adds its
  config-bound options with `TryAdd`, so an instance you registered earlier wins — and
  the `CredProx:CallerAuth` configuration section is then never read.
- **A pre-registered `CredProxHealthOptions`:** health is the one named switch decided at
  registration time — `CredProx:Health:Enabled` in configuration decides whether the probe
  loop and the `credprox` check are registered, and an instance you registered earlier does
  not change that decision. It still governs the probe interval and the expiry-warning
  window used by the probes that are registered. The scrubbing, error-normalisation and
  audit switches are read from the registered instance at run time, so there an instance
  you registered earlier does flip the feature.
- **A pre-registered `CallerTokenOptions`:** the caller-token extension is the deliberate
  exception to the `TryAdd` rule — it adds its config-bound options with `AddSingleton`,
  so the last registration wins and the fail-closed `MaxTokenAge` bound always comes from
  configuration; an instance you registered earlier is superseded
  ([ADR-0004](adr/0004-short-lived-scoped-caller-tokens.md)).

## The rules that make a package first-class

- **No `InternalsVisibleTo` outside the repository.** The built-in core opens its
  internals to this repository's own test, bench and fuzz projects and to the companion
  packages that ship in lockstep with it (`CredProx.Identity`, `CredProx.Azure`,
  ADR-0007); nothing outside this repository gets them. An extension package must
  compile against the public surface alone — if something you need is internal, that is
  an API gap worth an issue.
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
  Messages thrown out of a contract name the credential and the failure kind, never a
  value: CredProx's catch-alls report the exception's type (not its text) to the log and
  the health report, so a message that does carry a value is still not echoed — but the
  discipline is yours, and `CredProx.Testing`'s `CapturedLogSink.AssertNoSecretValues`
  proves it.
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
