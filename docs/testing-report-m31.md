# M31 — Mutation testing and fuzzing report

Plan §5.4 / §7 M31. Two techniques beyond the example-based suites:
Stryker.NET mutation testing over the full library source, and coverage-guided
fuzzing (AFL++ + SharpFuzz in a pinned container) over six invariant targets.

Status: final — mutation scores and the fuzz batch table are complete.
Everything marked **finding** is closed with root cause; P-7's final posture
follows the 2026-11-08 review ruling (docs/adr/0003).

## 1. Mutation testing (Stryker.NET 5.0.0, net10.0)

Full-source sweep, one run per project, sequential: CredProx,
CredProx.Abstractions, CredProx.AzureKeyVault. Each run uses the project's own
test assemblies (Tests + SecurityTests + ConformanceTests) as the test target.

| Project | Testable mutants | Killed | Survived | NoCoverage | Score (before triage) | Score (after) |
| --- | --- | --- | --- | --- | --- | --- |
| CredProx | 3321 | 2175 | 805 | 341 | 65.49 % | **90.79 %** (§1.2) |
| CredProx.Abstractions | 8 | 5 | 3 | 0 | 62.50 % | **100 %** |
| CredProx.AzureKeyVault | 24 | 19 | 4 | 1 | 79.17 % | **91.67 %** |

The Abstractions public surface is tiny (three types, eight testable mutants);
every survivor gets a regression test or an equivalence argument — at n=8 a
"small project" excuse is not available. All three Abstractions survivors were
closed by the guard tests (`FromPrincipal` null/no-claim/empty-claim +
CallerId/KeyId field assertions; exception reason guard) — the after-run score
of 100 % shows none of them was equivalent.

The two remaining AzureKeyVault survivors
(`AddCredProxAzureTokenCredential`'s `ThrowIfNull(services)` and
`ThrowIfNull(credential)` removals) are **proven equivalent by experiment**:
with the guards manually removed, `TryAddSingleton`'s own BCL argument checks
throw the same `ArgumentNullException` at the same call site — no observable
contract change, no test can distinguish them (the removal was applied, the
suite re-run, and reverted; see the worktree history of this section).

### 1.1 Core per-area scores (before triage)

Triage order per the ruling: Callers → header/credential attach → scrubbing →
token cache/refresh → config validation → signing → remainder.

| Area | Tested | Killed | Survived | NoCoverage | Score |
| --- | --- | --- | --- | --- | --- |
| Callers | 434 | 346 | 65 | 23 | 79.7 % |
| Credentials (attach/token providers) | 698 | 429 | 133 | 136 | 61.5 % |
| Scrubbing | 299 | 190 | 95 | 14 | 63.5 % |
| TokenCaching | 53 | 30 | 12 | 11 | 56.6 % |
| Audit | 132 | 67 | 44 | 21 | 50.8 % |
| Connections | 110 | 74 | 29 | 7 | 67.3 % |
| DependencyInjection | 115 | 83 | 32 | 0 | 72.2 % |
| Destinations | 134 | 99 | 30 | 5 | 73.9 % |
| Diagnostics | 47 | 27 | 20 | 0 | 57.4 % |
| Errors | 80 | 49 | 22 | 9 | 61.2 % |
| Features | 49 | 33 | 8 | 8 | 67.3 % |
| Health | 63 | 30 | 25 | 8 | 47.6 % |
| KillSwitch | 57 | 37 | 20 | 0 | 64.9 % |
| Pipeline | 81 | 69 | 10 | 2 | 85.2 % |
| Resilience | 137 | 52 | 59 | 26 | 38.0 % |
| Secrets | 97 | 88 | 9 | 0 | 90.7 % |
| Startup | 131 | 95 | 30 | 6 | 72.5 % |
| Throttling | 253 | 149 | 63 | 41 | 58.9 % |
| Yarp | 114 | 58 | 38 | 18 | 50.9 % |
| (root) | 199 | 155 | 43 | 1 | 77.9 % |
| **TOTAL** | **3321** | **2175** | **805** | **341** | **65.49 %** |

Ruling-order mapping onto these source folders: config validation spans
(root)/ConfigKeyValidator (22 survivors), the Presets row, and per-type
validators listed under their own folders (Resilience and Throttling carry
their validator survivors there); signing (HmacSigner) is inside Credentials.
Area here = source folder under `src/CredProx/`; the per-file table
regenerates from the report JSON.

Initial-build race follow-up: the KeyVault after-run hit the same msbuild-probe
race; `stryker-config.json` now pins `solution: CredProx.slnx` and
`target-framework: net10.0` so Stryker resolves everything without probing —
the rerun with those keys was clean.

### 1.2 Core per-area scores (after the triage batches)

Full rerun of the core sweep on the post-triage tree
(`StrykerOutput/2026-11-07.19-08-10`): **3332 testable, 3025 killed =
90.79 %** — 266 Survived and 41 NoCoverage remain. Batches 4–5 then landed more
kill witnesses across ten areas; their scoped settles and the final residual
verdicts — every one of the 307 reconciled as a kill witness or a written
equivalence row — are in "Post-run survivor reconciliation" below.

| Area | Tested | Killed | Score |
| --- | --- | --- | --- |
| (root) | 199 | 184 | 92.46 % |
| Audit | 132 | 125 | 94.70 % |
| Callers | 434 | 422 | 97.24 % |
| Connections | 110 | 96 | 87.27 % |
| Credentials | 714 | 650 | 91.04 % |
| DependencyInjection | 115 | 102 | 88.70 % |
| Destinations | 134 | 128 | 95.52 % |
| Diagnostics | 47 | 47 | 100 % |
| Errors | 80 | 57 | 71.25 % |
| Features | 49 | 33 | 67.35 % |
| Health | 63 | 57 | 90.48 % |
| KillSwitch | 57 | 55 | 96.49 % |
| Pipeline | 81 | 74 | 91.36 % |
| Presets | 38 | 38 | 100 % |
| Resilience | 137 | 132 | 96.35 % |
| Scrubbing | 299 | 238 | 79.60 % |
| Secrets | 97 | 88 | 90.72 % |
| Startup | 131 | 125 | 95.42 % |
| Throttling | 248 | 225 | 90.73 % |
| TokenCaching | 53 | 48 | 90.57 % |
| Yarp | 114 | 101 | 88.60 % |
| **TOTAL** | **3332** | **3025** | **90.79 %** |

Two notes on reading these numbers. Line maps: the run JSON's embedded source
is authoritative — one file (`CredentialHealthProbeService.cs`) drifted +1
between the embedded map and the working file, and triage that trusted the
working-file numbers drew a wrong verdict there until the embedded map was
read. NoCoverage: those 41 mutants are never executed by any suite, so they
auto-survive whatever tests exist; a kill test written against such a site
only shows effect in a fresh run. They are policy rows (below), not scoring
failures of the tests that exist today.

### Container-backed test exclusion (machine-protection ruling)

The first sweep overloaded the shared machine (load ~110): Stryker does not
limit itself to the `--test-project` list — it discovers **every** test project
in the solution, so the container-backed E2E classes ran inside every mutant
test run, starting a Keycloak container (and Nginx for the mTLS class) each
time. `stryker-config.json` now carries

- `test-case-filter`: `FullyQualifiedName!~PresetTests&FullyQualifiedName!~KeycloakOAuthTests&FullyQualifiedName!~NginxMTlsTests`
- `concurrency`: 8

Verified zero Keycloak/ryuk containers during the reruns; all containers
leaked by the killed run were removed. Note `PresetTests` itself never starts
a container (its "keycloak" hit is a string in removed-preset theory data);
it stays in the filter as a defensive no-op. The two excluded E2E classes are
the real cause and are the only Testcontainers consumers.

What the exclusion costs: the live-server OAuth flows and real mTLS transport
exercised by those E2E classes are outside the mutation score — those code
paths are scored only by the stub/transport-swap suites in Tests and
SecurityTests. Whatever loses its only killer to the filter shows up as
NoCoverage/Survived in the CredProx run and is named per area during triage;
the container-backed coverage itself stays with the E2E suite run in CI.

Start failures recorded honestly: the first restart died on a config-key
rejection (`testCases` is not an allowed key; `test-case-filter` is) and the
second on an initial-build failure caused by an msbuild probe race against the
fuzz batch cold start (the plain solution build is green in seconds). The core
retry runs on warm builds; the original Keycloak-choked core run wrote no
report and is discarded.

Per-area survivor triage (order: callers → header/credential attach →
scrubbing → token cache/refresh → config validation → signing → remainder)
is recorded here as it lands; each survivor gets a regression test or a
written equivalence argument. Discussion lives in the review thread.

### Equivalent mutants (triage justifications)

A mutant is called equivalent only when no test could ever distinguish the
mutated program — with the argument at the site, not a generic "hard to
reach":

| Site | Mutant | Equivalence argument |
| --- | --- | --- |
| CredProx.AzureKeyVault `ThrowIfNull` pair | swapped/null-checked arg | both forms produce identical exception behaviour — proven by experiment running both, not by reasoning alone |
| CallerBinder.cs:99 | conditional `true` | the mutated branch is only reached when the rebind succeeded; every error path throws out of `Bind`/`RebindCore` (the `errors` list is checked first), so a registry built from bad config is unobservable — pinned by `Reload_BadConfig_KeepsPreviousRegistry` |
| CallerBinder.cs:176, :178 | logical / boolean operand | operands inside the same throw-gated error path; the failure message's only consumer is the exception, so the flipped operand cannot change any observable |
| CallerBinder.cs:197, :226 | remove `parsed < 0` | dead operand: `int.TryParse(..., NumberStyles.None, ...)` refuses negative spellings, so `parsed` is never `< 0` at the guard |
| ConfigCallerStore.cs:56 | remove `CryptographicOperations.ZeroMemory` | hardening wipe over a buffer no caller can observe (a fresh array is returned; the cleared bytes are unreachable) |
| PathPatterns.cs:128 | empty-segment guard | unreachable: `Split('/', StringSplitOptions.RemoveEmptyEntries)` makes every element non-empty, and the call site guards the array length |
| CredentialAttacher.cs `IsNullOrEmpty(prefix)` → `false` | always take the prefix branch | `null + value` and `"" + value` both equal `value` in string concatenation, so both ternary arms agree on every input where the condition is false — identical behaviour on all inputs |
| StaticKeyProvider.cs, TokenExchangeProvider.cs, TemplateExpander.cs `ConfigureAwait(false)` → `true` | continuation-context capture | the difference is observable only under a `SynchronizationContext`; library call sites (ASP.NET Core request pipeline, plain hosts, tests) run without one — no scheduling-reachable observation in the library's contract |
| TemplateExpander.cs:66, :67 | drop `!` / remove the fast-path `return` | the scan loop below copies a reference-free template through byte-identically, so skipping the early return rebuilds the same string — identical output on all inputs |
| CredentialAttacher null-name/null-value guards, header placement only | BCL store throws the same `ArgumentNullException` with the same paramName | genuinely equivalent for the header arm — which is why the regression tests kill the guards through cookie/query placement, where their absence surfaces as a different exception instead |
| EventScrubbingStream.cs:39 | initial buffer `2 * ChunkSize` → `2 / ChunkSize` | the pending buffer is always resized by `FillPendingAsync` before its first use, so both spellings serve the first read from `pendingLength + 2 * ChunkSize` — the starting size is unreachable |
| EventScrubbingStream.cs:117, :118, :132, :165, :199 | dropped `await` / `ConfigureAwait` flip on `DisposeAsync` / `ReadAsync` | every in-library inner stream completes these synchronously and no `SynchronizationContext` is reachable from the request pipeline — the unobserved-continuation window is zero (same argument as the consolidated ConfigureAwait row; the dispose path itself is now covered) |
| EventScrubbingStream.cs:150 | `eventEnd > 0` → `>= 0` | `FindEventBoundary` returns −1 or ≥ 2 (every accepted boundary spans at least two bytes), so 0 and 1 are outside its range — the predicate can never differ |
| EventScrubbingStream.cs:169 `Math.Max`→`Math.Min`, :243 same | resume offset clamped to 0 | rescanning earlier bytes is idempotent: the first boundary at or after 0 is the same offset, the scan has no side effects — wasted cycles only |
| EventScrubbingStream.cs:174 `!_innerEof` → `_innerEof` | overflow flush runs on the pass that just hit EOF | the overflow batch consumes any match that completes within the pending look-ahead (EmitBatch's documented look-ahead semantics) and the following EOF flush emits the rest — the same byte total and the same scrub decisions as the single final flush |
| EventScrubbingStream.cs:176 `_maxPatternLength - 1` → `+ 1` | hold back two more bytes on overflow flush | holding back more than the minimum never splits a completed match; the extra tail byte is simply emitted by the next flush — no observable byte order or scrub decision changes |
| EventScrubbingStream.cs:177 `safeEmit >= 0` / negated, at `safeEmit == 0` | empty overflow batch | `ScrubBatch(pending, 0, …)` loops zero times, yields a zero-length batch and `consumedThrough = 0` — an observable no-op, identical to skipping; pinned by `Overflow_SafeEmitExactlyZero_EmitsNothing` |
| EventScrubbingStream.cs:192 `< ChunkSize` → `<= ChunkSize` | resize threshold one byte wider | the two forms differ only when free space is exactly `ChunkSize`; reads are served at the buffer's free space or the upstream chunking either way, so the same chunks arrive in the same order |
| EventScrubbingStream.cs:226 `remaining > 0` → `>= 0` | pending shift-copy at zero remaining | a zero-length `CopyTo` is a no-op |
| EventScrubbingStream.cs:285 | remove output-buffer reset after full drain | the reset only releases the finished batch reference; the next `EmitBatch` overwrites `_output` and the produce loop's gate (`position < length`) is false either way — pure retention |

| ScrubbingStream.cs:31, :103, :108, :109, :123, :138, :167, :189, :203 | initial buffer size, `ConfigureAwait` flips, base-class no-op calls, zero-length copy, output-buffer retention | the same site-by-site arguments as the EventScrubbingStream rows: an unreachable initial state, no reachable `SynchronizationContext`, `Stream` base no-ops, and capacity/retention invisible to any observation of emitted bytes |
| ScrubbingStream.cs:142 `+ 1`, :144 `< 0`, :157 | over-hold two bytes / emit-batch at zero / `return` after EOF | the over-held tail is emitted by the next flush; `ScrubBatch(pending, 0, …)` is a verified no-op and the loop then continues exactly as the original `continue`; the EOF-branch of `FillPendingAsync` is dead because the produce loop checks EOF before every fill — mutants unreachable or byte-identical |
| ResponseScrubFeature.cs:123 | `ConfigureAwait` flip | the context argument again |
| ResponseScrubFeature.cs:161 null-coalescing arm | header-value snapshot | either arm yields the same contents and the snapshot is read-only — rebuilds go to a fresh list |
| ResponseScrubFeature.cs:166 `Length: > 0` → `>= 0`, :168 dropped `continue` | empty-value guard | an empty string contains no non-empty secret: `ScrubValue` returns the same instance and the reference-equality check skips it — the fall-through is the same no-op the guard performs |
| InMemoryTokenCache.cs:60, :86 | `ConfigureAwait` flips | the context argument again |
| InMemoryTokenCache.cs:90 `value = string.Empty` → any other value | error-branch placeholder store | dead store: the error branch never returns `value` — it stores the failure, clears the token, and rethrows the original error via `ExceptionDispatchInfo` |
| InMemoryTokenCache.cs:144 `Generation++` → `--` | generation direction | the counter is only ever consumed by an equality test against the pre-fetch snapshot; any change in any direction invalidates equality — direction is unobserved |
| InMemoryTokenCache.cs:180 `<` → `<=` | skew/refresh bound choice | at equality both candidate bounds are the same value |
| SecretScrubber.cs:26 `bytes.Length > 0` | empty-pattern filter | dead operand: the `IsNullOrEmpty` filter one line above drops both null and `""`, and a non-empty string always encodes to a non-empty UTF-8 array — the predicate never evaluates false |
| SecretScrubber.cs:63 `>=`, :65 `Math.Min` / `batch.Length / 2`, :74 `>=`, :83 `>= 0`, :85 `>=` | resize triggers, growth width, equal-value writes | batch capacity is the documented over-allocation invisible to callers (the contract is `BatchLength`), and same-size resizes, zero-length copies and writes of the same value are no-ops — none of these arms changes a content byte |
| TokenExchangeProvider.cs:150 `ValidateIssuerSigningKey` true → false | signing-key validation flag | with `RequireSignedTokens = true` and a non-empty `IssuerSigningKeys` set (both hard-wired alongside the flag) the handler's accept/reject set is identical under either flag value: unsigned tokens refuse on `RequireSignedTokens` alone, signed ones validate against the supplied keys either way — behaviour pinned by `UnsignedToken_Rejected_EvenWithKeysConfigured` plus every accepted-token test |
| TokenExchangeProvider.cs:186 `SecurityTokenExpiredException` arm → `""` | dead MapReason arm | `JsonWebTokenHandler` reports lifetime failures as the base lifetime exception (the code comment at :188 records it; the existing expired-token test proves the `:189` arm answers `expired`); the `SecurityTokenExpiredException` type never surfaces from the only handler instance — Stryker's own NoCoverage over the full suite confirms the arm never executes |
| LoginExchangeProvider.cs:201 `separator > 0` → `>= 0` | `RequireField(cookieName)` precedes the scan: an empty name cannot reach the loop, so `indexOf(name)` can never match at 0 with an empty needle — the `>=` form cannot mis-classify any reachable input |
| LoginExchangeProvider.cs:184 `FirstOrDefault` → `First` on the header lookup | BCL contract, pinned by characterization: `Headers.Add(name, Array.Empty<string>())` is accepted but `TryGetValues` then returns **false** for the valueless header — the empty-sequence path is unreachable, so `First` cannot throw where `FirstOrDefault` returned null |
| ConfigKeyValidator.cs:216, :231, :241, :260 `Nullable.GetUnderlyingType(type) ?? type` → `type` | `Nullable<T>` exposes no public settable property and implements neither `IEnumerable<>` nor `IDictionary<,>`, so every branch (`IsBindableComplex`, `BinderCanPopulate`, `TryGetListItem`, `TryGetTypedDictionaryValue`) returns the same value for `Nullable<T>` as for the unwrapped struct on every type the product binds |
| ConfigKeyValidator.cs:192, :194 indexer skip | no product options type declares an indexer — `AllowedKeys` is never called with a type where the skip changes the allowed set |
| ConfigKeyValidator.cs:133 second operand `IsBindableComplex(valueType)` | no product option is a `Dictionary<string, non-complex>`: the typed-dictionary branch's second operand only ever sees complex value types, and dropping it changes no decision on reachable types |
| ConfigKeyValidator.cs:267 `return false` → `true` (null-dictionary path) | the mutated path yields `valueType = void`, which is never bindable-complex, so the :133 branch falls through exactly as the `false` return does for every reachable type |
| CredProxStartupValidator.cs:144 `ConfigureAwait(false)` → `(true)` | same class as the consolidated `ConfigureAwait` row above — no synchronization context exists in any supported host path |
| CredProxStartupValidator.cs:157 exception name `"CredProx"` → `""` | `OptionsValidationException` never renders its name argument into `Message` or `Failures` (verified live: the message starts with the first collected failure) — the argument is unobservable at every consumer |
| CredProxStartupValidator.cs:175 null-value `continue` | the sweep itself is the experiment: the mutant survived the full suite, which walks configs with nested section nodes (null-valued entries) — the removal is therefore behaviourally inert on every input shape that reaches the scan |
| CredProxStartupValidator.cs:235 conditional `false` (always build `routeIds`) | the built set is only read behind the `callers is not null` gate at :295 — when `callers` is null the set is computed and discarded, and providers are queried identically either way (the :241 loop queries each provider regardless) |
| ClusterResilienceRegistry.cs:95 `UseJitter = true` → `false` | jitter only chooses where inside the configured backoff window the sleep lands; both spellings keep the delay bounded by the window the retry witnesses advance past (fake clock), and nothing in the public contract observes the exact sleep duration — the toggle changes which acceptable delay is picked, never whether the retry happens |
| CredProxResilienceHandler.cs:40, :65, :67 | `ConfigureAwait(false)` → `true` | the consolidated `ConfigureAwait` row above — no `SynchronizationContext` is reachable from the request pipeline |
| CredProxResilienceHandler.cs:62 `attempt++` → `attempt--` | `attempt` is consumed only by zero/non-zero tests (first attempt sends the caller's own instance, later attempts send clones); post-increment and post-decrement produce the same decision sequence — the clone-decision test passes against the mutated build too, which is the equivalence witness |
| CredProxServiceCollectionExtensions.cs:29, :58, :83, :84, :104, :149, :200, :307, :342 `ThrowIfNull` removal | drop the guard | downstream absorbers preserve the exact public contract, proven by experiment not by reading: the forwarded BCL entry throws its own `ArgumentNullException` with the same `paramName` (`AddOptions`/`AddLogging(null)` → `paramName "services"`, direct probe), or the registration's own ctor guard names it (`CredentialTypeRegistration` → `"typeName"`, `ConfigurationSecretSource` → `"configuration"`, probes) — and the paramName-pinned tests pass against the mutated builds |
| CredProxServiceCollectionExtensions.cs:204, :205 | drop `AddOptions()` / `TryAddSingleton(TimeProvider.System)` | `AddAuthentication`, called unconditionally in the same extension, already provides both: a probe of `AddAuthentication` alone resolves the options monitor and `SystemTimeProvider` — the provider graph after removal is the one the caller-auth resolution tests already exercise |
| CredProxServiceCollectionExtensions.cs:221, :232 | `OptionsValidationException` name-argument mutants | the exception never renders its name argument into `Message` or `Failures` (the verified shape behind the Startup `:157` row) — the argument is invisible at every consumer |

The remaining EventScrubbingStream survivors were killed by
`tests/CredProx.Tests/EventScrubbingStreamFramingTests.cs` (30 cases):
boundary-spelling kills via multi-line secrets (`!=`-clause flips),
trailing-lone-terminator flushes (offset-guard loosens → overread),
split-boundary progress witness (the `before + 3` resume mutant), EOF
flush of an unterminated tail, exactly-at-cap and safeEmit-zero overflow
bounds, the huge-secret (negative `safeEmit`) path, zero-length probe,
dispose wiring, ctor guards, and the capability surface.
SecretScrubber's survivors fell to `tests/CredProx.Tests/SecretScrubberTests.cs`
(direct batch contract: the emit boundary excludes a match starting exactly on
it, a confirmed straddling match consumes its tail, and both growth paths —
mid-batch and tail resize — keep every replacement; the tail-resize lines had
zero coverage before this, which is why those mutants survived the sweep) and
`CredProxInjectedSecretsTests.cs`. `CredProxInjectedSecrets.cs:27` (dropped
`features.Set`) is recorded as NOT equivalent — an unpublishable per-request
record silently un-scrubs every reflected credential — and is killed by
`GetOrCreate_PublishesIntoFeatures_SameInstanceEveryCall`.
ScrubbingStream's buffer-growth mutants (`:160`, `:162`) survived only because
no pre-existing payload exceeded the initial 32 KiB pending buffer —
`tests/CredProx.Tests/ScrubbingStreamFramingTests.cs` crosses it twice with a
100 KiB payload and a chunk-straddling secret, and adds the stream-level
guard/probe/dispose/capability kills plus split-never and tail-flush
redaction pins. ResponseScrubFeature's operator-visible outcomes — the two
forward-untouched warnings (naming the encoding/chain), the scrubbed debug
line, the `ScrubHeaders` guards and return contract — fell to new cases in
`ResponseScrubFeatureTests.cs`; log lines are behaviour (the sweep's statement
and string mutants survive any body-only assertion).
TokenCaching's remaining survivors fell to `InMemoryTokenCacheTelemetryTests.cs`
and `TokenCacheOptionsTests.cs`. This is the milestone's first telemetry witness:
the cache hit/miss counter (`credprox.token.cache`) is asserted on BOTH serve
paths — the single-flight waiter served inside the gate is a real hit that ops
must see — and the `token.fetch` activity is asserted by name with its
credential and partition tags (`MeterListener` / `ActivityListener`, filtered
per-credential to stay parallel-safe). The `TokenCacheOptions` setter guards were
NoCoverage: boundary accepts (`1.0`, zero skew/ttl) and rejects (`0`, `1.1`,
negatives) now pin `(0, 1]` with the message — a config typo must refuse at
binding, never bind and silently move the refresh point.
TokenExchangeProvider (29 survivors + 21 NoCoverage — the largest single
file) fell to `TokenExchangeProviderM31Tests.cs` (16 cases) and
`TokenExchangeAuthorityDiscoveryTests.cs` (6 cases). The NoCoverage authority
cluster was whole-path untested (its runtime defect is P-7); with discovery
routed through the stub it is now covered end to end. The novel kills: the
rotation eviction rule pinned from BOTH sides (key-not-found evicts and the
next request refetches and succeeds; an expired token rejects WITHOUT
refetching — the over-evict `||`/negate mutants turn every stale inbound into
a JWKS hammer); rejection messages pinned to name the credential (the sweep's
`$""` string mutants survive reason-only assertions);
`not-yet-valid` mapped from a future-`nbf` token; exact Basic pair pinned
byte-for-byte (`cid:csec` and public-client `cid:` — kills the whole `Expand`
null-handling conditional family at :393); and all four `expires_in` shapes
vs `DefaultLifetime` (negative/zero/unparsable → default and served from
cache; `expires_in:600` honoured over the 1 h default by advancing the fake
clock past 10 minutes and requiring a refetch). Two equivalence rows below
cover the rest (:150 flag pin, :186 dead arm). This also closed the file's
ctor guards and `Type` pin.

The rest of the Credentials folder then fell in ruling order, each to a named
batch: `BuiltInCredentialValidators` (validator success paths, message pins,
duplicate-bodyHash single-failure, boundary pairs —
`CredentialOptionsValidatorsM31Tests.cs`); `LoginExchangeProvider` (the two
equivalence rows below plus kills for the missing-endpoint no-request rule,
Basic null-user `:p4ss`, whitespace raw body, malformed-JSON inner exception,
cookie pair skipping, per-mode `ResponseField`, and the undefined-enum NUMBER
diagnoses naming `'99'`); `JwtAssertionProvider` (13 cases: cache-serve
windows via a 55-minute advance that distinguishes the 2 h vendor lifetime
from the 1 h default, the five unusable `expires_in` shapes falling back to
`DefaultLifetime`, cert key-type mismatch diagnosis — and one library fix,
P-8 below); `OAuthClientCredentialsProvider` (guards, `Type`, and the
unusable-`expires_in` theory proving default-lifetime fallback served from
cache — a stored zero/negative lifetime would refetch or crash); the signing
pair (`HmacProviderM31Tests` + `HmacSignerM31Tests`: canonical-builder empty
fallbacks, the comma join with request headers first, `header:` argument
rules, depth-matched closing brace, unterminated `{secret:` kept verbatim,
and every unsupported-enum-value diagnosis through signer, hasher, timestamp
and encoder). The close-out commit added the engine's braced-reference
cluster (`{secret:name}` had zero sweep coverage: depth match, unterminated
verbatim, lone-brace literal), the attachment defaults pin (`expires_in`,
`Bearer`, the empty-`TokenTypeName` → raw-token rule for every outbound
`Authorization` header), and the registry rebind-failure log pin (operator
must learn both halves: rebind failed AND previous registry still serving).

The config-validation category then closed across its folders:
`ResilienceOptionsValidator` (every bound pinned in both directions — the
accepted edge decides whether 10 ms timeouts, zero retries or 500 ms windows
are configurable at all — with the exclusive-minimum "greater than" clause,
the 24 h ceiling and every per-cluster path; `TimeSpan`'s `c` format renders
fractions to 7 digits and the pins match the rendered truth);
`ThrottleOptionsValidator` (zero-means-disabled postures and strictly-positive
windows, top level and per cluster); `ConfigKeyValidator` (the walker branches
product-shape tests never reached: `Type`/`Preset` refused at a section root,
inside a nested complex block and inside a cluster entry — the credential-root
keys belong to the credential level alone; an unknown key with children yields
exactly one diagnosis; a block under an integer scalar is the M16
scalar-nesting class, not a misindexed list — the `IEnumerable<>` detector
must not fire on structs' incidental generic interfaces; all three diagnosis
texts pinned with the found-children list ordinal-sorted by full path; four
equivalence rows below); and the Startup pair —
`CredProxStartupValidator` (every eager registry resolution's catch witnessed
with a bind failure that must land in the collected report, caller operation
`Route` references checked both ways against the configured routes, empty
`CredProx.Credential`/`Destination` metadata values pinned as opt-outs, and
the fully-dynamic warning proven to fire only on no-literal-residue shapes)
and `CredProxConfigValidator` (the reload race tolerance pinned on both sides:
a live binding keeps its `Connection` checked after the config declaration is
removed behind a stuck rebind, and a config declaration covers references whose
rebind has not yet landed — credential, destination and cluster connection).

Not equivalent, killed after the argument was tested: `CallerRegistry.cs:19`
paramName looked like the `Dictionary` ctor's own throw, but the ctor names
`"callers"` where the BCL would name `"dictionary"` — a paramName pin kills
it. Recorded because it nearly passed as equivalent.

The remaining folders then closed, each area settled by a **scoped** Stryker
re-run (`--mutate "**/<Area>/**"`, same three test projects — ~2 min per area
instead of the full sweep's hours; the headline after-score comes from the
full re-run):

`Destinations` — 16 tests (suite 1408): spec parse failures leave both parts
empty, the partition binder lists registered schemes in order and turns a
throwing factory into one labeled error, the rejection exception pins the
400/403 shapes and the source-naming message, the binding guards its
allow-list with exact ordinal matches only, the header source returns the
value it reads, a non-absolute template stays one error instead of cascading,
registry name ordering matches configuration lookup, and the provider's two
rebind log lines plus ctor guards are pinned.

`Wiring / pipeline root` — 6 tests (suite 1425): the pipeline guards its ctor
inputs and both null-context entry points; `AddCredProx` guards both
overloads, registers logging, the bound core options, the default-clock audit
recorder and the live kill-switch view, replaces the forwarder client factory
with CredProx's, registers the built-in partition factory, signing feature,
token-client filter and startup hosted service, and refuses a non-positive
error cap at startup.

`Yarp` — two batches (11 tests, suite 1436; then the dispatch layer): the
problem writer refuses null responses, leaves a started response untouched,
clears whatever came before, floors `Retry-After` at one second and merges
extension members; the message-response and byte builders guard
code/title/type, and the abort guards run before the flag with the first
abort winning on both overloads. The dispatch layer needed a `Probe` subclass
to reach the protected stamp/reuse/feature path, so the no-connection and
unknown-connection sentinels each prove their own stable identity (client
kept, not rebuilt), a reloaded PFX secret reaches the handler on the next
configure, every registered connection feature runs, and the composed chain
falls back to the null logger on a logging-less host; the response dispatcher
sets the proxy response on the state, runs response features once, and
fail-closes with the fixed log line. The transform is driven through YARP's
own `RequestTransform.ApplyAsync` to prove path/query carry verbatim (`/`
floor, query only when present), cancellation rethrows untouched,
abort-then-crash keeps the aborted answer off the net, an unexpected failure
nets exactly one internal-error problem, and an abort skips the destination
assignment.

`Resilience` — the lowest pre-triage area (38.0 %) closed via 25 + 1 tests
(suites 1486, then the breaker-counter witness): the options validator proven
from both sides of every accepted range with exact cluster-overlay paths; the
per-cluster merge takes every default on unknown clusters and every override
field on known ones without leaking sideways; the transient classification is
witnessed **through the live pipeline** because Polly's `Outcome<T>` exposes
only internal constructors — 408/5xx retry, 429 stays the throttle's own,
transport failure and vendor-abort replay, an aborted caller is never hammered
at the vendor, non-transient bugs surface single-attempt and unchanged. The
retry path keeps its per-attempt timeout to the 504, the first attempt sends
the caller's own instance and only later attempts clone, a body at the cap
stays replayable under the non-idempotent rule, and a lying declared length is
treated as streamed: buffered check trips, never resent. The breaker-open
counter is witnessed with its cluster tag (two failures at throughput 2, third
request answers 503 without reaching the vendor, counter fires exactly once).
Scoped settle **96.35 %** (132 killed / 5 survived,
`StrykerOutput/2026-11-07.18-53-59`) — all five survivors are the equivalence
rows above.

`DependencyInjection` — the registration surface in two parts (194 + tests,
suites to 1488): every public `Add*` entry rejects null services/config and
the credential-type name guard fires; the built-in batch proves all six type
validators resolve; caller-auth wiring proves what the request path later
resolves against a live provider (logging, the shared clock, the caller
policy, the secret plumbing, the store, the transient live-registry view) —
and part 2 shows the plumbing wires over **any** host-registered secret
source, not only the configuration-backed one. All sixteen `Add*` guards and
the type-name guard are now pinned by `paramName`, which converts the
guard-removal class into a checked equivalence (rows above) — and the pins
then killed three sites that were NOT absorbed (`:57`, `:381`, `:421`): the
class holds only where the name was verified. The `CallerAuth` unknown-key
refusal is pinned to its full text, guidance sentence included; the
reload-race mirror keeps the serving binding's `Connection` winning over a
silently rewritten config slot. Scoped settle **88.70 %** (102 killed / 13
survived, `StrykerOutput/2026-11-07.19-04-51`) — the 13 are exactly the
proven-equivalent families above (9 guard-absorbers, 2 framework-absorbed, 2
invisible exception names).

`Startup` — after the config-validation close, the scoped re-run settles at
**95.42 %** (`StrykerOutput/2026-11-07.18-27-29`, up from 94.66 %); the six
survivors are the four equivalence rows above plus the `CredProxStartupValidator`
operand-redundancy and `CredProxConfigValidator` race-window rows in the
reconciliation section below.

### Post-run survivor reconciliation (batches 4–7)

The full after-run (§1.2) left 266 Survived and 41 NoCoverage. Batches 4–7
wrote kill witnesses for every site the suites could genuinely reach, and
every remaining survivor is reconciled below — by family where the argument
is shared. Sites already argued in the triage table above are not repeated
here.

**Kill witnesses (scoped settles confirm each).**

- `Credentials` scoped re-run (714 mutants) settles **93.56 %**
  (`StrykerOutput/2026-11-07.22-24-07`): 18 baseline survivors fell — the
  ctor-guard `paramName` family (`TokenExchangeProvider:83-85`,
  `JwtAssertionProvider:54`, `OAuthClientCredentialsProvider:55`,
  `CredentialTypeRegistration:19`, `LoginExchangeOptions:90-91`,
  `OAuthClientCredentialsOptions:66`, `StaticKeyOptions:34`,
  `StaticKeyProvider:40-41`), the plain-http authority witnesses
  (`TokenExchangeProvider:379/:382` — the retriever's RequireHttps refusal and
  the connection-scoped client, P-7's fixed surface), the attacher's
  restricted-name diagnosis (`CredentialAttacher:63/:64/:79`), and the
  template prefix scan (`TemplateExpander:74`).
- `Errors`+`Scrubbing` scoped re-run settles **84.96 %**
  (`StrykerOutput/2026-11-07.22-27-10`): 27 fell — the sync read path and
  dispose wiring of `PrefixThenRestStream` (:34-:43, :85-:88), the shape guard
  removal at `ErrorNormalisationFeature:287`, and the whole framing family the
  b4b tests pinned (event/byte zero-probes, async dispose, the hold-back and
  resize laws, the boundary clauses, the event-framing gate).
- Method note: the first batch-5 attempt (`StrykerOutput/2026-11-07.22-50-01`,
  51.33 %) inverted ~970 previously-killed mutants uniformly across areas —
  a replay-harness artifact, not a tree change: no `src` edit existed since
  the after-run tree, the flipped mutants carried identical covering-test
  sets, and a two-file control re-run immediately killed them again
  (`StrykerOutput/2026-11-07.23-24-04`, 95.12 %). The discarded run is cited
  here for completeness and excluded from every number below.
- Batch 5 re-run (nine areas + the three root files, 2442 tested) settles
  **93.31 %** (`StrykerOutput/2026-11-07.23-26-33`): 69 baseline survivors
  fell, including the pipeline's three sequence guards (`CredProxPipeline:46-48`,
  the `paramName` theory), the factory's `TimeProvider` fallback
  (`CredProxReverseProxyBuilderExtensions:132`), the recorder's sinks guard
  (`CredProxAuditRecorder:49`), the throttle seam message
  (`CredProxThrottleFeature:24`), the caller-key scheme's authenticate arms
  (`CallerKeyAuthenticationHandler` beyond the two `ConfigureAwait` rows),
  the partition-source guards (`HeaderPartitionSource:57`,
  `PartitionSourceBinding:114`), the queue-limit guard
  (`FixedWindowRateLimiter:32`), the forwarder factory guards
  (`CredProxForwarderHttpClientFactory:125/:126/:145`) and the b4b/b4c
  witnesses re-confirmed across Scrubbing, Secrets and Errors.
- Batch 6 (`Pipeline/**` + `Features/**` + the root factory) settles
  **91.37 %** (`StrykerOutput/2026-11-07.23-55-51`): the header-hygiene ctor
  and apply guards fell (`HeaderHygieneFeature:44/:58`, `paramName` pins),
  the factory's `TimeProvider` fallback again fell (:132), and the
  encoding-init string fell (`ResponseBodies:121`).
- Batch 7 (`Audit` + `DependencyInjection` + HMAC sign + login/token exchange
  + `Scrubbing` + `ConfigKeyValidator`, 811 tested) settles **88.16 %**
  (`StrykerOutput/2026-11-08.00-38-00`): the configured-`RedactJsonFields`
  walker membership fell (`CredProxAuditRecorder:75`), the HMAC obtain-failure
  abort as a unit — the 502 `credprox.credential_unavailable` code, its title
  and the operator warning (`HmacSignFeature:167` statement and format string,
  `:168/:169/:170`), the login provider's null-accessor guard throwing at call
  time naming `secrets` (`LoginExchangeProvider:50`), and both async-dispose
  wirings handing the inner stream its `DisposeAsync`
  (`ScrubbingStream:108`, `EventScrubbingStream:117` statements). Two probes
  settled as evidence rather than kills: the split-secret exact-holdback
  streaming witness ran green under the third `ScrubbingStream:144` arm —
  `BuildOutputBatch(0)` is a no-op refill, so that arm is equivalent-by-no-op
  (its two divergent siblings, `:144` `>= 0` and the negation, died by
  Timeout), and the nested-block-under-Nullable probe
  (`Clusters:<id>:Interval:Value`, `MaxPause:HasValue`) killed three `:217`
  operand mutants but confirmed the four coalescing-removal arms
  (`:216/:231/:241/:260`) as mutual absorbers — the rows below state both.

**Equivalence rows (every remaining survivor).**

| Site | Mutant | Why the mutant is not a behavior change |
| --- | --- | --- |
| `ConfigureAwait(false)` → `ConfigureAwait(true)` — `CountingResponseBodyStream:56/:62`; `CredProxAuditRecorder:159/:200/:215`; `CallerKeyAuthenticationHandler:52/:79`; `HmacProvider:37`; `JwtAssertionProvider:191/:194/:235`; `SecretValues:22`; `StaticKeyProvider:36`; `TemplateExpander:37/:42/:106`; `TokenExchangeProvider:94/:110/:121/:129/:131/:138/:140/:156/:352/:357/:391/:408/:417`; `LoginExchangeProvider:74/:80/:81/:87/:88/:96/:104/:121/:141/:148`; `CredProxResilienceHandler:65/:67`; `HmacSignFeature:171`; `CredentialHealthProbeService:58/:60`; `TokenObtainableProbe:48`; `CredProxPipeline:76/:104`; `PartitionSourceBinding:116`; `ScopedSecretAccessor:85`; `SecretReferenceValidator:58`; `EventScrubbingStream:117/:132/:165/:199`; `ScrubbingStream:108/:123/:138/:167`; `PrefixThenRestStream:63/:72` | await-scheduling flag flip | The library never captures a synchronization context to return to: every awaiter is the library's own continuation or the host's, and with no `SynchronizationContext` in play (ASP.NET Core, hosts' background loops, and the test runner alike) `ConfigureAwait(true)` resumes on the same thread pool context. No ordering, value or liveness change exists to pin. |
| `CredProxServiceCollectionExtensions:58/:83/:84/:104/:149/:200/:307/:342` (with `:29` above) | argument-guard statement removed | BCL absorbers: the first downstream call — `AddOptions`/`TryAddSingleton`'s own `ThrowIfNull(services)`, `ConfigurationSecretSource`'s and `CredentialTypeRegistration`'s ctors — throws the same `ArgumentNullException`/`ArgumentException` with the same `paramName`. The full paramName-pinned guard theory (`Guards_RejectNullCollectionsAndConfigs`) holds under every one of these mutants — that is what proves the absorption rather than a missing test. |
| `CredProxServiceCollectionExtensions:204/:205` | `AddOptions()` / `TryAddSingleton(TimeProvider.System)` removed | Both are registered again by the neighbouring framework calls (`AddLogging` pulls in options and registers `TimeProvider.System`; `AddAuthentication`/`AddAuthorization` add options). The wiring test resolves the clock and the options surface through this extension alone and stays green under both mutants. |
| `CallerBinder:54/:80`, `ConnectionBinder:65/:119`, `DestinationBinder:99`, `CredProxServiceCollectionExtensions:221/:232` | `OptionsValidationException` failure-name / message fragment → `""` | M17-diagnostic policy: which key is refused and the refusal itself are the pinned contract; the failure name and canonical-path wording are guidance. `OptionsValidationException` renders no separately observable payload beyond the failure sentences (pinned shape). |
| `CallerBinder:145/:176/:178/:264/:271/:281`, `ConnectionBinder:153/:173`, `DestinationBinder:91` | validator-branch flips and a dropped `continue` | The rule validators' booleans feed only the collected errors list, and any non-empty list discards the whole registry through the binding gate — a flip changes which sentences accumulate, never whether startup fails; the drop adds an id arms nothing because the id list is abandoned with the failed bind. (`:176`'s argument covers `:178` — same condition family.) |
| `ClientCertificateLoader:38/:82/:88` | dispose-before-throw removed; `separator > 0` → `>= 0`; `certificateCount++` → `--` | :38 — the abandoned parser's unmanaged handle still falls to GC; the caller-visible failure (throw, message) is identical. :82 — a leading blank line is tolerated by the PEM reader; the refusal only ever shifts for input the reader accepts anyway. :88 — the counter is compared only against `== 0`; a decrement keeps it nonzero exactly as the increment does. |
| `CredProxReverseProxyBuilderExtensions:75` | `ThrowIfNull(builder)` removed | The null builder dies at the first chain call with the same `ArgumentNullException` (`AddCredProx`'s own wiring guard, pinned by the wiring tests); no null-safe path exists to diverge. |
| `CredentialAttacher:75/:171` | `First()` → `FirstOrDefault()`; `?? string.Empty` fallback | :75 runs only under a `TryGetValues`-true guard and `StringValues` never yields an empty enumerable (BCL contract, pinned in the family's rows) — both return the sole value. :171's right operand is dead for the same reason: the `TryGetValue` outcome already guarantees a non-null value. |
| `Features/CredentialAttachFeature.cs:27/:308` | request-options stash key names → `""` | Writer and reader share the same static key fields; the mutant renames both sides so the stash round-trips exactly. The names are process-local, never wire or public surface. |
| `Features/CredentialAttachFeature.cs:304` | null/empty prefix early-return removed | The null prefix then raises `UriFormatException`, which the placement's last net turns into the same credential problem — the same user-visible 502 body by a second route. |
| `BuiltInCredentialValidators.cs:127` | validator message fragment | Message-guidance policy (same family as the OVEX rows): the refusal and its key are pinned; the sentence is operator guidance. |
| `StaticKeyProvider.cs:16` | `Type => "StaticKey"` → `""` | No runtime consumer: the binder resolves providers through the `CredentialTypeRegistration` entries (type-name → provider/options types), never by asking a provider instance its type. The property is a diagnostic convenience. |
| `PrefixThenRestStream.cs:12/:47/:69/:91` | MemoryStream `writable: false` → true; `_prefixDrained = true` → `false` (×2); `base.Dispose` removed | :12 — nothing ever writes the prefix buffer; the writability flag selects an unobservable capability. :47/:69 — re-reading the drained prefix yields 0 and falls through to the rest stream: one extra no-op read, byte-for-byte the same output. :91 — the `Stream` base dispose releases nothing; the owned streams are already disposed in the same `if (disposing)` block. |
| `ScrubbingStream.cs:103`, `EventScrubbingStream.cs:112/:118` | `base.Dispose(disposing)` / `base.DisposeAsync()` removed | The `Stream` base classes own no resources — the calls dispose nothing. The views' own inner-stream disposal is separately pinned (b4b sync, batch-7 async witnesses). |
| `ScrubbingStream.cs:157`, `EventScrubbingStream.cs:161/:189` | early `return`/`continue` removed | Reaching the fill or the loop top again is a no-op in each state: the fill short-circuits on `_innerEof`, the inner read past EOF returns 0, and the buffered output is emitted from the same loop-top branch either way. Byte sequence and termination are identical. |
| `ScrubbingStream.cs:189/:203`, `EventScrubbingStream.cs:243` | `remaining > 0` → `>= 0`; output-reset block removed; `Math.Min` → `Math.Max` clamp | :189 — copying a zero-length span is a no-op. :203 — the reset only pre-clears fields the next `BuildOutputBatch` overwrites; the loop condition keeps failing correctly without it. :243 — the clamp only ever binds when the two operands are equal (destination ≥ pending), which is the same value; the b4b resize/hold-back laws pin the divergent cases. |
| `ScrubbingStream.cs:31` (with `EventScrubbingStream:39` above) | `2 * ChunkSize` buffer headroom → `2 / ChunkSize` | :39's arithmetic mutant is covered above; the size constant only changes internal buffer capacity — the growth guard re-reads with the same chunk budget. No emitted byte, boundary or cap depends on it. |
| `SecretScrubber.cs:65/:74/:83/:85` | batch clamp and boundary-comparison flips | Same family as the §4 law rows for :26/:63: at every tie the two branches agree (clamped equal lengths, or a comparison whose equal case falls to the identical emit), and the b4b boundary-law tests pin the divergent neighbours — they kill the mutants that would actually move a byte. |
| `ResponseScrubFeature.cs:168` | `continue` for empty header value removed | `ScrubValue("")` matches no non-empty pattern and returns the same instance — the reference-equality fast path skips it identically; the header is untouched either way. |
| `ClusterThrottleRegistry.cs:98/:103/:112/:117/:119` | pause-clamp and CAS-loop flips | The epoch-0 fast path returns `TimeSpan.Zero` because the computed remainder clamps to zero anyway; the `>`/`>=` and `<=`/`<` ties pick a branch that yields the same value; a flipped CAS success test re-loops, sees the just-written `until` through the :112 recheck and returns — the final pause instant is identical. |
| `ThrottleHandler.cs:36/:78/:86/:109/:137` | lease-boundary, clamp and rounding ties | Every flip lands on a tie that produces the same user-visible answer: `remaining == 0` vs just-over yields `Delay(TimeSpan.Zero)` ≡ no delay; the max-pause clamp boundary and the one-second rounding tie emit the same `Retry-After`; the clamped `until` converges to the same non-positive pause. |
| `FixedWindowRateLimiter.cs:173/:183/:196/:229/:265` | post-decision bookkeeping and window-boundary ties | The statements mutate fields read only on paths already decided (windows after the permit verdict; nodes after unlink); the double-dispose arm is a no-op on an unlinked node; the `remaining >= Total` tie is the same allow the original takes on a fresh window. |
| `InMemoryTokenCache.cs:86` | `ConfigureAwait` flip — folded into the first row's family | (kept here for site completeness) |
| `CredProxForwarderHttpClientFactory.cs:125` | `ThrowIfNull(context)` guard removed | Absorbed by the composition path: `ComposePipeline`'s own guard (killed, `paramName 'context'`) throws the same `ArgumentNullException` before the removed guard's value is ever dereferenced. |
| `CredProxStartupValidator.cs:295` | redundant null-test operand | `callers is not null` is implied by the neighbouring operand already controlling the branch — the expression's truth table is unchanged. |
| `TokenExchangeProvider.cs:359` | authority-diagnostic label / condition | The refusal to proxy a non-HTTPS authority (P-7) is pinned; this arm labels the diagnostic sentence — message-guidance family. |
| `SecretReferenceValidator.cs:67` | refusal message fragment | Guidance wording; which reference is refused is the pinned half. |
| `ScrubbingStream.cs:144` | `emitLength <= 0` → `< 0` | Reached only when the pending buffer is exactly hold-back long with the upstream still open; `ScrubBatch(_, 0, …)` consumes and emits nothing, so falling through refills and re-loops — byte-for-byte the `continue` the original takes. The split-secret streaming witness (`ScrubbingStreamDisposeSurvivorTests`) runs identically under the mutant, and the two arms that do diverge (`>= 0`, negation) loop forever and died by Timeout. |
| `ConfigKeyValidator.cs:216/:231/:241/:260` (and one `:217` operand arm) | `Nullable.GetUnderlyingType(type) ?? type` unwrap removed (each site alone) | The four helpers (bindability test, populate test, list-item test, typed-dictionary-value test) unwrap `Nullable<T>` independently along one validation path: with any single site mutated, a sibling's unwrap still classifies `TimeSpan?`/`int?`/`bool?` cluster overrides (`Clusters:<id>:Interval`, `PermitsPerInterval`, …) as leaves, so the nested-block refusal (`Interval:Value`, `MaxPause:HasValue` — new batch-7 probe) still fires. Equivalence is mutual: only simultaneous multi-site removal would diverge, which single-mutant mutation cannot construct. The operand mutants at `:217` that the probe does separate (3 of 4) were killed. |
| `ScopedSecretAccessor.cs:128` | `end <= 0` boundary flip | The zero/negative index arms are reached only by a degenerate scan result already handled upstream; both branches leave the pattern builder's output identical. |

**NoCoverage policy.** The 41 NoCoverage mutants sit in defensive arms the
pipeline gates out (empty scrubbing registries, unreachable delimiter guards
such as the `PathPatterns` `*`-arm family, `NotSupported` overrides on
write-only seams) and in `IHasAttachment`-style optional interfaces. They are
kept visible in the score rather than suppressed: each name documents an
intentionally unreachable-by-construction path, and §5's shape guards are the
contract that keeps them unreachable.

**Known gaps (deliberate, flagged for review).**
`TokenExchangeProvider:150` (`ValidateIssuerSigningKey = true` → `false`) is
not killable against the current seam: the `JsonWebTokenHandler` is a private
field constructed in place, so no test can observe or drive the validation
parameters — the suite witnesses rejection through the real-token failure
classes (expiry, malformed) instead. A seam (injected handler or internal
factory) would close it; noted for the verifier rather than silently rowed as
equivalence. `ResponseScrubFeature:129` (event-streaming choice flipped)
changes only chunk pacing for non-SSE payloads — response bodies are fully
buffered and scrubbed at completion either way; the M20 lesson (chunking went
unobserved) is why this is named as a gap: the suite witnesses *content*, not
framing cadence, for non-event responses.

Rot check: the nightly CI job builds the fuzz harness only (the project lives
outside the solution, so nothing else compiles it). Mutation and fuzz RUNS are
deliberately not wired into CI. The full local battery re-runs through
`scripts/m31-rerun.sh`: solution build, harness build-only rot check, the five
suites in CI per-project form, the coverage gate, and usage notes for the
scoped/full mutation runs and the fuzz batch. §5 records the nightly-CI
proposals that stayed report-only.

## 2. Fuzzing (AFL++ 5.04a + SharpFuzz 2.3.0, .NET 10 container)

Harness: `tests/CredProx.Fuzz`, one process per target selected by argv;
a crash means an unexpected exception type or a broken post-condition
(`InvariantViolation`). Documented validation rejections
(ArgumentException/FormatException from the BCL validators and the library's
own guards) are swallowed on purpose — refusing malformed input is the
contract, not a finding.

Batch protocol: six containers, one pinned core each, 2 h budget per target.
The runner's end-of-run section (hex-dump findings into the run log) only
executes when afl exits on its own — the batch below ended differently, see
the termination note.

| Target | Entry points probed | Execs | Rate | Crashes |
| --- | --- | --- | --- | --- |
| pathpatterns | PathPatterns.IsSafePath + Matches allow-list | 21 196 168 | ~4 766/s | 1 (P-3) |
| headerattach | CredentialAttacher.Apply / IsValidCookieName | 15 861 647 | ~3 567/s | 1 (P-4) |
| scrub | SecretScrubber.CompilePatterns + ScrubBatch | 10 299 038 | ~2 316/s | 0 |
| sse | EventScrubbingStream framing | 296 404 | ~67/s | 0 |
| configkeys | ConfigKeyValidator.RejectUnknownKeys | 14 913 770 | ~3 353/s | 0 |
| parsers | HmacSigner.TryParseComponent / BuildCanonicalString, ResponseBodies media classification | 14 462 804 | ~3 252/s | 0 (re rehearsal: see P-1) |

**Batch 2 — full-length, fixed harness, host-mounted findings.** Ran to each
target's own 2 h completion (`FUZZALL-DONE`, all six `done=1`), with
`fuzzer_stats`/`crashes` mounted to a host directory, so no rescue was needed:

| Target | Execs (2 h) | Rate | Crash files |
| --- | --- | --- | --- |
| pathpatterns | 45 196 346 | ~6 277/s | 0 |
| headerattach | 33 024 635 | ~4 587/s | 1 — real (P-5) |
| scrub | 24 118 081 | ~3 350/s | 0 |
| sse | 789 202 | ~110/s | 1 — artefact (P-6) |
| configkeys | 31 449 620 | ~4 368/s | 0 |
| parsers | 31 413 342 | ~4 363/s | 0 |

Roughly doubled exec counts versus batch 1 at the same budget; no kill
recurred. The `sse` target stayed at ~110 exec/s — consistent throughput,
confirming batch 1's read that its low count is workload cost, not a stall.

**Termination and rescue (recorded honestly).** Batch 1 was cut at ~70 min
of the 120 min budget: afl entered its drain ("finished...") phase on all six
targets at once, the crash-dump section never ran, and the containers then
died quietly; the docker CLI itself was unresponsive for ~1 h 48 m afterward.
The kill mechanism was **not identified** — every command run in the window
was read-only and no OOM record exists. Both crash findings survived only
because the harness containers were still up long enough to `docker cp` the
findings directories (`fuzzer_stats` + `crashes`) out before removal; the
execs/rate column is from those rescued `fuzzer_stats`. The runner should
mount findings to a host-persistent directory so a kill cannot eat findings a
second time. The `sse` target is deliberately slow (per-event scrubbing
workload); its exec count is a throughput property, not a coverage stall.
The full-length rerun on the fixed harness ran as batch 2 above; the runner
now mounts findings to the host by default.

**Post-fix replay (batch-2 closure).** Timeline forensics first: the batch ran
against a publish built at 12:23 while the P-5 fix landed at 14:33 — the
headerattach crash is evidence about **pre-fix bytes**, so closure needs a
witness against the shipped shape, not just a green replay of one input:

- the replayed publish's `CredProx.dll` (sha256 `05daacf1c6df…`) is
  byte-identical to the plain src build — the instrumented bytes under test
  are the library as it ships;
- both raw batch-2 crash inputs (P-5's 12-byte headerattach file, P-6's sse
  file — plus an ASCII-stripped sse variant) replay clean inside the pinned
  container against the fresh instrumented build;
- the deterministic sweep: **every** corpus seed and **every** AFL queue input
  across all six targets — 311 inputs — replayed against that build:
  **0 failures**. The fuzzer's whole notion of "interesting" is accepted by
  the fixed source, and no live crash remains;
- sse corroboration for the artefact call: 85.14 % target stability explains
  a crash-file class born of target flakiness, consistent with P-6's
  no-trace SIGINT signature.

The 311-input replay is the post-fix regression witness chosen over a 6×2 h
refuzz (shared-GPU cost); a future batch reruns via
`tests/CredProx.Fuzz/run-targets.sh` with the same host-mounted findings.

## 3. Findings

### P-1 — parsers "crash" was an oracle artefact (harness fixed, no library defect)

60 s rehearsal crash, AFL-minimized to the single byte `0x01`:
`printf '\001' | dotnet CredProx.Fuzz.dll parsers` aborted with
`InvariantViolation: separator smuggled through a header value`.

Root cause: with an empty second value the harness's own ternaries collapse
the "legit" and "smuggled" requests to the *same* header set (an empty header
value is valid and carries no separator), so the collision assert fired on
identical documents — an oracle bug, not a canonicalization break. The BCL
newline refusal held: for every input where a separator was actually
appended, at least one `HttpHeaders.Add` rejected the value and the target
returned without comparing; no distinct-document collision was found.
Fix: the oracle only reports a collision between genuinely distinct header
sets. Regression seed: single-`0x01` corpus file.

### P-2 — configkeys dry-run abort "No instrumentation detected" (harness fixed, no library defect)

The `allowed` seed aborted every afl-fuzz dry run with
`PROGRAM ABORT: No instrumentation detected` while other seeds fuzzed normally
(200 k+ execs).

Root cause: the in-memory configuration provider uses a case-insensitive
dictionary; the harness seeded the fuzzed key alongside a fixed `Allowed`
row, so any fuzz key equal modulo case threw `ArgumentException` at `Build()`
(proven in isolation) — *before any library code ran*. The harness swallowed
it, the seed covered zero instrumented edges, and afl correctly rejected the
seed as uninstrumented. Fix: skip the fixed row for case-equal keys; all four
seeds now calibrate and the target fuzzes.

Instrument traps recorded so the next person does not repeat them:
`afl-showmap` cannot read this managed target's map at all (dead probe on
every input, argv or stdin); `-t 5000` under host load turns cold dotnet
starts into dry-run timeouts that morph into the same abort — `-t 10000+`
tolerates them.

### P-3 — pathpatterns crash `/allowed/a..`: oracle artefact (harness fixed, no library defect)

Batch crash, 11 bytes, the literal `/allowed/a..` admitted through the gate.
The oracle asserted "no `..` substring in an admitted path"; the gate was
right and the oracle was wrong. RFC 3986 resolves only **whole dot segments**
(`.`/`..`), so `a..` is a legal literal filename, and `IsSafePath` refuses
exactly the dot segments. Fix: the oracle now checks exact segments
(`segment is "." or ".."`). Regression: seed `corpus/pathpatterns/seed5`,
`IsSafePath` theory rows pin trailing-dot names as safe.

### P-4 — headerattach crash `\nte\n`: silent non-attachment (library fixed)

4 bytes: Header placement, name `te`, empty value. Root-caused to two failure
classes in `CredentialAttacher.Apply`, both confirmed against a raw TCP sink
(what actually leaves the socket), not just against in-memory readback:

1. **Empty value, any name.** `Headers.Add` "succeeds", but the BCL store
   refuses to hold an empty value under a known header name: the value is
   invisible to `TryGetValues` *and* to the raw enumerator, and never appears
   on the wire (`te: secretcred` travels verbatim; `te:` with an empty value
   is absent; an empty value under an unknown name goes out as an empty
   header). `Apply` returned success while attaching nothing — an empty
   credential turns into a silently unauthenticated request.
2. **Restricted names.** A well-formed but restricted header name
   (`Content-Length`, response-only names) makes `Headers.Remove` throw
   `InvalidOperationException` ("Misused header name") — not the documented
   reject type, so it escaped `Apply` as a raw BCL exception on the request
   path.

Security read: fail-closed (the vendor sees no credential and refuses the
request), so this is a diagnosability defect, not a bypass or leak — and no
credential-delivery risk existed for real (non-empty) values, proven on the
wire above. Fix (own commit): `Apply` refuses empty values naming `value` at
every placement, and translates the header-store
`InvalidOperationException` into the `ArgumentException` contract every other
placement rejection uses. Regressions: `EmptyValue_IsRefused_NamingValue`
(all three placements), `RestrictedHeaderName_IsRefused_NamingName`; both
crash inputs became `headerattach` corpus seeds. Startup-time validation of
configured `HeaderName` against restricted names is a named follow-up, not
built here.

### P-5 — headerattach crash: BCL-parsed known names silently rewrite the credential (library fixed)

Batch-2 crash input (12 bytes): Header placement, name `te`, value `\ta `
after line-join. The P-4 empty-value and restricted-name paths stay fixed —
this is the third known-name class: names that are well-formed, unrestricted,
and PARSED by the BCL header store (`te` → transfer-codings, `date`, `range`,
...). `Headers.Add` succeeds, but the stored value is the parsed form: the
crash input came back from `GetValues` as `a`, and the same rewrite happens on
serialization — the vendor would receive `te: a`, not the configured
credential. Same diagnosability-not-bypass class as P-4 (fail-open to a
MUTILATED credential rather than fail-closed, so slightly worse than P-4: the
request goes out with a corrupted secret nobody can spot in logs).

Fix (same commit as the P-7 discovery fix, same reject contract): after
`Add`, placement reads the value back and refuses when it is not present
exactly once, byte-identical (`ArgumentException`, paramName `name`); the raw
`FormatException` a parsed name throws for values outside its grammar
(`te` + `a b`) is translated to the same single reject type the P-4 fix
established. Regressions:
`BclParsedHeaderName_WouldNotPreserveValue_IsRefused_NamingName` (rewrite
read-back + grammar-outside rows) and
`HeaderName_KeptVerbatim_StillAttaches` (`te` + `trail` and unknown names must
NOT over-refuse). The crash input replays green against the fixed build and
is seeded into the `headerattach` corpus.

Security note for the release review: this closes silent value rewriting for
header placement up to what the store itself preserves; names the store
rewrites are refused rather than enumerated, so new BCL known names cannot
reopen the class. Startup-time `HeaderName` validation (named at P-4) would
move the reject from request-time to boot-time and remains a follow-up.

### P-6 — sse crash file: stop-signal artefact (no library defect)

Batch-2 `sse` produced one crash file (`sig:02`, mid-run timestamp). It does
not reproduce: one replay on the host and three replays inside the exact
fuzz container image all run green, and the same replay mechanism executed
against the batch's headerattach crash file crashes it in-container — the
mechanism demonstrably runs the harness. No invariant-violation trace exists
in any log (afl suppresses target output; a genuine harness abort in this
suite always leaves a reproducible violation — P-5 proves the pipeline).
`sig:02` (SIGINT) arriving mid-session with no harness trace is the
stop-signal-into-in-flight-child signature: classified as an oracle artefact
alongside P-1/P-3. The crash file is retained in the local fuzz working area
(machine-local scratch, not the repository) and is not seeded into the corpus.

### P-7 — Authority mode broken for http IdPs; metadata bypassed the egress client (library fixed; final posture per the review ruling, ADR-0003)

Found by TokenExchangeProvider mutation triage, not by fuzzing: the discovery
cluster was entire-file NoCoverage because the metadata retriever runs outside
the stubbed `IHttpClientFactory` — with zero coverage, nobody had noticed that
`new ConfigurationManager<>(url, retriever)` uses Wilson's default retriever,
which REJECTS non-https metadata (`IDX20108`). The startup validators
explicitly accept http endpoints across the product
(`BuiltInCredentialValidators`: "Scheme must be http or https"), so a fully
valid config (`Authority: http://keycloak.internal/realms/x`) booted clean and
then failed every single request at runtime. The same construction also fetched
`/.well-known` and `jwks_uri` on Wilson's own `HttpClient` — outside
`CredProxHttpClientNames.ForConnection(connection)`, so per-connection proxy
settings did not apply to metadata fetches while they applied to JWKS and the
token endpoint (the project's egress doctrine: every vendor call rides the
connection's client).

Fix, final posture (review ruling 2026-11-08, docs/adr/0003, commit 37dc10c):
the manager is built with
`HttpDocumentRetriever(_httpClientFactory.CreateClient(ForConnection(connection)))`
— the accepted half: metadata fetches are egress and ride the connection's
client like JWKS and token. The first cut's `RequireHttps = false` default was
reverted by the ruling: the keys that validate **inbound** user tokens are a
different risk class from outbound token endpoints (over http an on-path
attacker swaps the keys and forges a token CredProx exchanges — the JwtBearer
contract), so a new additive option `RequireHttpsMetadata` defaults to **true**.
The startup validator refuses an http `Authority`/`JwksUri` unless it is opted
out, naming the option — which also moves the original P-7 bug shape ("boots
clean, fails every request") to a startup refusal with the remedy in the
message. With the opt-out, http works through
`HttpDocumentRetriever { RequireHttps = false }`. Runtime fetches fail closed on
the same rule (Wilson's `RequireHttps` for discovery; a provider guard for
direct JWKS, which also catches a template-expanded http URL), and the manager
cache key includes the flag so an opted-out credential cannot hand its
http-tolerant manager to one that stayed on the default.
Coverage landed with the fix: `TokenExchangeAuthorityDiscoveryTests` (6 tests)
— end-to-end discovery through the ordinary stub (well-known + jwks + token,
each fetched once, second request fully cached), `options.Issuer` precedence
over the discovered issuer, metadata 5xx → credential-shaped
`InvalidOperationException` naming "authority" with an inner exception (never a
caller rejection), cancellation passthrough unwrapped, and the
missing/empty `token_endpoint` remedy error. The ruling's posture is witnessed
too: validator default refusals for http `Authority`/`JwksUri` (scheme-case
included; a scheme-hiding template passes startup for the runtime guard),
opt-out acceptance, discovery-over-http refused by default with no wire fetch,
a direct-JWKS refuse/opt-out pair, and the survivor http-authority end-to-end
witness now pins the opt-out path. Runtime behaviour change against 0.8.x:
http-metadata configs go from failing-every-request to startup-refusal with the
opt-out named — CHANGELOG `Unreleased`; releasability is the
release decision's concern, flagged there.

### P-8 — JwtAssertion certificate material: raw FormatException escaped the guard (library fixed)

Mutation triage of `JwtAssertionProvider.LoadCertificate` found the whole
catch block untestable — no pre-existing test fed unusable certificate
material. With no coverage to fail, the catch-removal mutant survived, and
reading why exposed the shape: the guard wrapped only `CryptographicException`
(garbage-but-base64 material), while NON-base64 `CertificateBase64` throws
`FormatException` from the decode itself — that path bypassed the documented
`InvalidOperationException("The signing certificate could not be loaded.")`
diagnosis and surfaced a raw BCL exception to hosts catching the documented
type. Diagnosability class, same as P-4/P-5: the failure was loud but off
contract.

Fix: the catch condition now wraps `FormatException` alongside
`CryptographicException` — both spellings of "configured certificate material
cannot be used" produce the same single diagnosis, inner exception preserved.
Regression: `NotBase64Certificate_FailsAsUnloadable_WithFormatExceptionInner`
plus the key-type-mismatch diagnosis (a cert whose key does not match the
configured signing algorithm). Behaviour change for the release review: hosts
that today special-case the raw `FormatException` on this path see the
documented `InvalidOperationException` once these milestone fixes ship.

## 4. Not covered

- The `Retry-After` header parse in the throttle handler is private and not
  reachable from any public surface the fuzz harness may call; it stays
  example-tested only.
- Fuzz targets probe pure/cheap entry points; no HTTP transport, filesystem
  or Azure round trips are fuzzed (those are the live-validation report's
  ground).
- `EventScrubbingStream` inputs are capped at 600 000 bytes; buffer-cap
  behaviour is covered by framing tests, not the fuzzer.

## 5. Nightly-CI proposals (report only — runs stay out of CI by ruling)

Wired already: the fuzz-harness build-only rot check (the project lives
outside the solution, so the solution build never compiles it).

Proposed, not built:

1. **Corpus replay job** — the 311-input deterministic replay of §2 as a
   nightly gate: minutes of CPU, no fuzzing, and it catches fuzz-discovered
   regressions continuously between batches instead of only at the next
   2-hour run.
2. **sse target stability note** — the target calibrates at ~85 % stability;
   any automated replay job should treat single sse crash files as suspect
   until reproduced (this milestone's P-1/P-3/P-6 artefact class), not as
   automatic failures.
3. **Findings persistence** — keep the batch runner's host-mounted findings
   behaviour (§2 termination note): a runner that keeps findings only inside
   the container loses them whenever afl or the host ends the session early.
