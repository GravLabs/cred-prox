# Contributing to CredProx

CredProx is a credential-handling YARP extension: configuration-only vendor
integration, token caching, caller authentication, and resilience. Everything that
counts as done is pinned by a test or a gate listed below — if the gate is green and
the behavior is covered, the change is done.

## Getting set up

- [.NET 10 SDK](https://dotnet.microsoft.com/download) — the only target framework
  (`net10.0`); there is no multi-targeting.
- Docker — needed for the E2E tests (Keycloak, nginx mTLS) and most samples.

On a fresh clone, pack the libraries into the local feed first: the samples in the
solution consume CredProx as packages from `artifacts/packages`, so the solution build
cannot restore them until that feed exists.

```bash
for p in src/*/; do dotnet pack "$p" -c Release -o artifacts/packages; done
dotnet build CredProx.slnx -c Release   # must stay 0 warnings / 0 errors
```

Packaging gate — baseline validation must pass, not just the build (build 0W/0E does
**not** cover pack; the nupkg is produced even when validation fails):

```bash
dotnet pack src/CredProx -c Release -o /tmp/packgate   # must exit 0 (CP0001 type removed / CP0002 member removed = breaking vs baseline)
```

Run it from a clean build or force validation (`touch src/CredProx/CredProx.csproj`): the
up-to-date stamp does **not** track `CompatibilitySuppressions.xml`, so a repack after
editing suppressions can silently skip it (CI is unaffected — clean builds).

SDK 10.0's APICompat has no `[Experimental]` awareness — every baseline removal bites:
CP0001 for a removed type, CP0002 for a removed member. Intentional removals live in the
project's `CompatibilitySuppressions.xml` (auto-detected; regenerate with
`/p:ApiCompatGenerateSuppressionFile=true`); a CP0001/CP0002 you did not intend is a real
breaking change (PUBLISHING.md rule).

## The gates a change must keep green

| Gate | Command | Needs Docker |
|---|---|---|
| Unit + integration | `dotnet test tests/CredProx.Tests` | no |
| Security (property tests, secret-leak checks) | `dotnet test tests/CredProx.SecurityTests` | no |
| Conformance (built-ins through `CredProx.Testing`) | `dotnet test tests/CredProx.ConformanceTests` | no |
| E2E (Keycloak, nginx mTLS via Testcontainers) | `dotnet test tests/CredProx.E2ETests` | yes |
| Load (throttling, breaker, cache under load) | `dotnet test tests/CredProx.LoadTests` | no |
| Sample cells — every sample's offline behavior | `dotnet test tests/CredProx.SampleSmokes` | yes |
| Coverage (floors below) | the three lines under it | no |
| Pack + APICompat | the `dotnet pack` gate above | no |
| Consumer-compat, plain default run | `scripts/consumer-compat.sh` | yes |

Every sample also has a one-line `smoke.sh` that runs its own cells from the test
project. CI runs each sample's cells as its own filtered process **and** one
unfiltered whole-project run (`dotnet test tests/CredProx.SampleSmokes`): only a
single-process run starts every fixture side by side, which catches a stack or host
that one fixture leaves behind for the next. A whole-project run needs the samples'
vendor stub projects, which are not in `CredProx.slnx`: building
`dotnet build tests/CredProx.SampleSmokes -c <configuration>` builds them, so run it
first in the configuration you smoke in (never pair the whole-project run with
`--no-build` on a tree where they were not built). `tests/CredProx.LiveTests` is
likewise outside `CredProx.slnx`: it talks to real vendors only on demand via
`scripts/live-run.sh` and must never run in CI (the guard cells in `CredProx.Tests`
keep it out of the solution and out of every workflow).

Coverage gates run from the repo root:

```bash
rm -rf TestResults
dotnet test tests/CredProx.Tests -c Release --collect:"XPlat Code Coverage" --results-directory TestResults
dotnet test tests/CredProx.ConformanceTests -c Release --collect:"XPlat Code Coverage" --results-directory TestResults
python3 build/coverage-gate.py "TestResults/**/coverage.cobertura.xml"
```

Floors: `CredProx` core ≥ 90% line / ≥ 80% branch; add-on packages ≥ 80% line;
`CredProx.Abstractions` and `CredProx.Testing` ≥ 80% line. A PR that lowers coverage
below a gate fails CI. Coverage is a floor, not the goal — the suites named above are
the definition of "tested".

## Versions

`main` carries the next version with a `-dev` suffix (say `0.16.0-dev`). Release prep
sets the real number at tag time; until then nothing on `main` is publishable. The
public API is stable within a minor version (`0.x.*`); API still settling carries
`[Experimental("CREDPROX001")]` until 1.0.

## Code rules that CI enforces

- `Nullable` and `ImplicitUsings` on; **warnings are errors**; XML docs on every public
  member (missing docs are warnings, and warnings are errors).
- **Error messages, logs and audit records must never contain secret values** — only
  names and references. This is tested (`tests/CredProx.SecurityTests`); new code paths
  that touch secrets need a matching leak check.
- Fail closed: an unresolvable reference, unknown credential or broken allow-list refuses
  the request; it never passes traffic through unauthenticated.

## Layout

```
src/CredProx.Abstractions/   public contracts (stages, providers, sources) — no dependencies
src/CredProx/                the core host pieces: pipeline, cache, secret refs, the StaticKey,
                             Hmac and LoginExchange credential types, caller API keys, audit
src/CredProx.Identity/       add-on: the OAuth credential types + inbound caller authentication
                             by short-lived Entra/OIDC tokens
src/CredProx.Operations/     add-on: throttling, retries/circuit breakers, health probes
src/CredProx.Azure/          add-on: the TokenCredential credential type
src/CredProx.Testing/        fakes + conformance suites for plugin authors
tests/CredProx.Tests/        unit + integration
tests/CredProx.SecurityTests/ tests/CredProx.ConformanceTests/ tests/CredProx.E2ETests/
tests/CredProx.LoadTests/    the suites named in the gate table
tests/CredProx.SampleSmokes/ every sample's offline cells, one fixture per sample
samples/                     production-shape hosts: short config-driven Program.cs, offline
                             settings in appsettings, a StubApi/ stand-in project where the
                             vendor is stood in locally, one smoke.sh wrapper per sample
tools/aca-live-harness/      the live-verification harness against Azure Container Apps
                             (four roles in one image, driven against the real tenant; not a sample)
docs/                        guides; docs/vendors/ carries copy-paste vendor config blocks
```

## Adding a vendor

The library ships **no built-in vendor presets**: every vendor lives in its own
isolated sample — README, explicit config, a StubApi stand-in (or WireMock) where it
runs offline, and its cells in `tests/CredProx.SampleSmokes`. To add one:

1. Create `samples/<Vendor>` modeled on the closest existing sample (`OAuthKeycloak`
   is the OAuth client-credentials shape with an offline stand-in; `ADP` adds a client
   certificate; `LoginExchange` shows partitions and the allow-list). Write the
   credential block out in full — no preset references.
2. Add it to `CredProx.slnx` and the CI sample build loop
   (`.github/workflows/ci.yml`), plus its `smoke.sh` wrapper and its cells.
3. A preset is a **distribution** choice for preset authors, not a library feature:
   package fixed vendor facts (token endpoint, client-auth style, response shape,
   conventional `secret:` name) as `CredProx:Presets` config or a custom `IPresetSource`
   in your own package. Everything tenant- or app-specific stays with the host, and every
   preset field can be overridden field by field. A preset must never introduce a secret
   reference the host has to guess: name the conventional `secret:` reference and
   document the required host fields.

## Writing a package

Start with [docs/extending.md](docs/extending.md): the seams, the rules that make a
package first-class (no `InternalsVisibleTo`, fail-closed registration, secret
hygiene, conformance suites). The template is
[`samples/CustomPlugin`](samples/CustomPlugin) — a complete custom credential type in
~50 lines with its test suite.

## Pull requests

- One change per PR; describe the behaviour it promises and the tests that pin it.
- CI runs build, all suites, coverage gates and the offline samples. Samples build against
  the **packed `.nupkg`**, so packaging mistakes fail CI too.
- Security-sensitive changes (token cache, secret scoping, allow-lists, caller auth,
  signing) get an explicit security pass against the boundaries listed in
  [SECURITY.md](SECURITY.md).
