# Upgrading CredProx

Do-this steps for the version jumps you are actually on, plus how to read a future
CHANGELOG entry as an operator. CredProx is pre-1.0: a minor version may carry
breaking changes, and every one of them ships under a `### Breaking` heading with
its replacement — nothing breaks silently.

## 0.11 → 0.12: the package split (the one that needs work)

0.12 moved features out of the single `CredProx` package into small add-on
packages (ADR-0005, `CHANGELOG.md:311-387`). Config keys and credential `Type`
values did not change. For each feature you use, add the package and its one
setup call (`CHANGELOG.md:116-134`):

| You use | Add package | Add call |
|---|---|---|
| core pipeline, `StaticKey`, caller policy | `CredProx` | `AddCredProx(builder.Configuration)` |
| `OAuthClientCredentials`, `TokenExchange`, `JwtAssertion` | `CredProx.OAuth` | `AddCredProxOAuth()` |
| `Hmac` | `CredProx.Hmac` | `AddCredProxHmac()` |
| `LoginExchange` | `CredProx.LoginExchange` | `AddCredProxLoginExchange()` |
| outbound throttling, resilience, health probes | `CredProx.Operations` | `AddCredProxThrottling(builder.Configuration)`, `AddCredProxResilience(builder.Configuration)`, `AddCredProxHealthProbes(builder.Configuration)` |
| caller keys | `CredProx.CallerKeys` | `AddCredProxCallerAuthentication(...)` |
| caller tokens | `CredProx.CallerTokens` | `AddCredProxCallerTokenAuthentication(...)` |

Then expect three things (`CHANGELOG.md:311-387`):

1. **Startup fails naming a missing package** if you configure
   `CredProx:Throttling`, `CredProx:Resilience` or `CredProx:Health` without
   `CredProx.Operations` (or `CredProx:CallerAuth`/`CredProx:CallerToken` without
   their packages). That is fail-closed, both directions — fix the reference, do
   not delete the config to silence it.
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
behaviour (`CHANGELOG.md:80-95`):

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
(`CHANGELOG.md:105-112`). A per-request allocation fix ships in the same release
(`CHANGELOG.md:99-104`).

## 0.10 → 0.11, in one line

Recompile only: the caller contract surface collapsed to single constructors with
optional parameters (`CHANGELOG.md:402-479`). The one call-site edit is the
identity deconstruct: `var (callerId, keyId, clientId) = identity;`.

## Reading the next CHANGELOG entry

- `### Breaking` — removals and signature changes with named replacements and a
  migration line. Every shipped package (ten: core, Abstractions,
  AzureKeyVault, CallerKeys, CallerTokens, Hmac, LoginExchange, OAuth,
  Operations, Testing) gets its own entry where it changed.
- `### Changed` — behaviour shifts like the two 0.13 notes above. Read every
  bullet even when you compile clean; these do not surface as build errors.
- `### Fixed` — check whether a workaround you wrote is now the bug; 0.13's
  rotation gate is that shape.
- Allocation notes — the bench gate prices documented per-request deltas; a
  change there tells you the byte budget moved, not the behaviour.
- After any bump: rebuild (moved types surface as compile errors), run your test
  suite, and rebuild the samples path against the new packages — the samples
  consume packages exactly as a host does (`PUBLISHING.md` for the feed route).
