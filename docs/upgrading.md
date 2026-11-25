# Upgrading CredProx

Do-this steps for the version jumps you are actually on, plus how to read a future
CHANGELOG entry as an operator. CredProx is pre-1.0: a minor version may carry
breaking changes, and every one of them ships under a `### Breaking` heading with
its replacement — nothing breaks silently. Opt-in feature surfaces get their own
operator pages under `docs/operations/` — usage metering, for instance, is at
[operations/metrics.md](operations/metrics.md).

## 0.11 → 0.12: the package split (the one that needs work)

0.12 moved features out of the single `CredProx` package into small add-on
packages (ADR-0005, the `### Breaking` entries of the `## [0.12.0]` section in
`CHANGELOG.md`). Config keys and credential `Type`
values did not change. From 0.15 the packages group by dependency instead
(ADR-0007) and the setup is one entry plus one chained call per add-on package;
reaching 0.15 from before 0.12, this is the shape to write:

| You use | Add package | Add call |
|---|---|---|
| core pipeline, `StaticKey`, `Hmac`, `LoginExchange`, caller keys | `CredProx` | `AddCredProx(builder.Configuration)` — the core's own features are configuration-driven |
| `OAuthClientCredentials`, `TokenExchange`, `JwtAssertion`, caller tokens | `CredProx.Identity` | `.AddIdentity()` chained on the entry |
| outbound throttling, resilience, health probes | `CredProx.Operations` | `.AddOperations()` chained on the entry — each leg reads its own section |
| the `TokenCredential` type | `CredProx.Azure` | `.AddAzure(credential)` chained on the entry |

Then expect three things (same `### Breaking` entries of `CHANGELOG.md` `[0.12.0]`):

1. **Startup fails naming a missing package** if you configure
   `CredProx:Throttling`, `CredProx:Resilience` or `CredProx:Health` without
   `CredProx.Operations`, a `CredProx:CallerToken` section without
   `CredProx.Identity`, or a caller under `CredProx:Callers` with no way to
   authenticate — keys from the core, caller tokens from `CredProx.Identity`, or
   your own `WithCallerAuthenticator<T>()`. That is fail-closed, both directions —
   fix the reference, do not delete the config to silence it.
2. **Moved types are binary-breaking**: recompile against the new assemblies.
   `CredProxAuth.CallerKeyScheme` / `CredProxAuth.CallerTokenScheme` are replaced
   by `CallerKeyOptions.Scheme` / `CallerTokenOptions.Scheme`; the `CallerKey`
   model type is gone; `CallerDefinition` no longer carries `Keys` or
   `TokenClientIds`.
3. Caller-key and caller-token validation now rides startup **and every
   configuration rebind** — a live edit that would have been ignored before can
   now keep the previous generation serving.

## 0.12 → 0.13: no breaking changes; read two behaviour notes

There is no `### Breaking` section in 0.13.0. Two `### Changed` entries alter
behaviour (the `### Changed` entries of `CHANGELOG.md` `[0.13.0]`):

1. `CredProx:Health:Enabled=false` now means off: neither the probe loop nor the
   `credprox` health check is registered. A platform probe that counted on the
   check existing while disabled now fails — wire the check only where health is
   on.
2. Response features sharing a stage run after the secret scrubber regardless of
   registration order. A host that registered its own response feature before the
   scrubber now sees scrubbed bytes — which is the point.

And one `### Fixed` entry is an upgrade incentive: 0.12.0 shipped a caller-key
rebind gate that missed rotations arriving through upper-cased configuration
sources, so a rotated key kept working until restart. If you rotate caller keys,
0.13 is the fix — see [operations/credential-rotation.md](operations/credential-rotation.md) §2
(the matching `### Fixed` entry of `CHANGELOG.md` `[0.13.0]`). A per-request
allocation fix ships in the same release (the other `### Fixed` entry of that section).

## 0.13 → 0.14: two renamed config keys

Two credential keys were renamed and the old spelling refuses startup
(the `### Breaking (experimental API)` entries of `CHANGELOG.md` `[0.14.0]`):

1. `LoginExchange` session lifetime: `Lifetime` → `DefaultLifetime`.
2. `TokenExchange` accepted inbound audience: `Audience` → `InboundAudience`.

The other `Audience`/`Lifetime` keys — the `JwtAssertion`, `CallerToken` and
`OAuthClientCredentials` bags — keep their names.

## 0.14 → 0.15: the reshape (the one that needs work)

The packages group by dependency (ADR-0007) and registration collapses to one
entry plus one chained call per add-on package (`CHANGELOG.md` `[0.15.0]`); the table
under 0.11 → 0.12 is that shape.

1. **Package ids moved.** CredProx.CallerKeys, CredProx.Hmac and CredProx.LoginExchange
   (now in CredProx), CredProx.OAuth and CredProx.CallerTokens (now CredProx.Identity)
   and CredProx.AzureKeyVault (now CredProx.Azure) have been removed from the package
   registry; reference the replacement package instead. Because those versions are gone, a
   host that still references one of them cannot restore it on a clean machine or CI agent;
   switch to the replacement package before the next clean build.
2. **One entry, chained add-ons, no-arg hookup:** `AddCredProx(builder.Configuration)`,
   then `.AddIdentity()`, `.AddOperations()` and `.AddAzure(credential)` as needed, and
   `AddReverseProxy().…AddCredProx()` — no arguments; a no-arg call with no prior entry
   fails startup naming it. The granular `AddCredProx*` registrations that were public
   in 0.14 are internal now; the compiler points at the entry.
3. **Moved contracts are binary-breaking:** `ICallerStore` and `CallerKeyMatch` now
   live in `CredProx.Abstractions`; recompile against them.

## 0.10 → 0.11, in one line

Recompile only: the caller contract surface collapsed to single constructors with
optional parameters (the `### Breaking` entries of `CHANGELOG.md` `[0.11.0]`). The one call-site edit is the
identity deconstruct: `var (callerId, keyId, clientId) = identity;`.

## Reading the next CHANGELOG entry

- `### Breaking` — removals and signature changes with named replacements and a
  migration line. Every shipped package (six: core, Abstractions, Identity,
  Operations, Azure, Testing) gets its own entry where it changed.
- `### Changed` — behaviour shifts like the two 0.13 notes above. Read every
  bullet even when you compile clean; these do not surface as build errors.
- `### Fixed` — check whether a workaround you wrote is now the bug; 0.13's
  rotation gate is that shape.
- Allocation notes — the bench gate prices documented per-request deltas; a
  change there tells you the byte budget moved, not the behaviour.
- After any bump: rebuild (moved types surface as compile errors), run your test
  suite, and rebuild the samples path against the new packages — the samples
  consume packages exactly as a host does (`PUBLISHING.md` for the feed route).
