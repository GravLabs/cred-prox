# Contributing to CredProx

CredProx is a credential-handling YARP extension: configuration-only vendor integration,
token caching, caller authentication, and resilience. The design and the definition of
"done" live in [`docs/credprox-plan.md`](docs/credprox-plan.md) — read the section your
change touches before writing code.

## Getting set up

- [.NET 10 SDK](https://dotnet.microsoft.com/download) — the only target framework
  (`net10.0`); there is no multi-targeting.
- Docker — needed for the E2E tests (Keycloak, nginx mTLS) and most samples.

```bash
dotnet build CredProx.slnx -c Release   # must stay 0 warnings / 0 errors
```

Packaging gate — baseline validation must pass, not just the build (build 0W/0E does
**not** cover pack; the nupkg is produced even when validation fails):

```bash
dotnet pack src/CredProx -c Release -o /tmp/packgate   # must exit 0 (CP0001 = breaking vs baseline)
```

Run it from a clean build or force validation (`touch src/CredProx/CredProx.csproj`): the
up-to-date stamp does **not** track `CompatibilitySuppressions.xml`, so a repack after
editing suppressions can silently skip it (CI is unaffected — clean builds).

SDK 10.0's APICompat has no `[Experimental]` awareness — every baseline removal is
CP0001. Intentional removals live in the project's `CompatibilitySuppressions.xml`
(auto-detected; regenerate with `/p:ApiCompatGenerateSuppressionFile=true`); a CP0001
you did not intend is a real breaking change (PUBLISHING.md rule).

## Running the tests

| Suite | Command | Needs Docker |
|---|---|---|
| Unit + integration | `dotnet test tests/CredProx.Tests` | no |
| Security (property tests, secret-leak checks) | `dotnet test tests/CredProx.SecurityTests` | no |
| Conformance (built-ins through `CredProx.Testing`) | `dotnet test tests/CredProx.ConformanceTests` | no |
| E2E (Keycloak, nginx mTLS via Testcontainers) | `dotnet test tests/CredProx.E2ETests` | yes |
| Load (throttling, breaker, cache under load) | `dotnet test tests/CredProx.LoadTests` | no |

Coverage gates (plan §5.3) run from the repo root:

```bash
rm -rf TestResults
dotnet test tests/CredProx.Tests -c Release --collect:"XPlat Code Coverage" --results-directory TestResults
dotnet test tests/CredProx.ConformanceTests -c Release --collect:"XPlat Code Coverage" --results-directory TestResults
python3 build/coverage-gate.py "TestResults/**/coverage.cobertura.xml"
```

Floors: `CredProx` core ≥ 90% line / ≥ 80% branch; add-on packages ≥ 80% line;
`CredProx.Abstractions` and `CredProx.Testing` ≥ 80% line. A PR that lowers coverage
below a gate fails CI. Coverage is a floor, not the goal — the plan's §5.2 test list is
the real definition of "tested".

## Code rules that CI enforces

- `Nullable` and `ImplicitUsings` on; **warnings are errors**; XML docs on every public
  member (missing docs are warnings, and warnings are errors).
- Public API that is still settling carries `[Experimental("CREDPROX001")]` until 1.0.
- **Error messages, logs and audit records must never contain secret values** — only
  names and references. This is tested (`tests/CredProx.SecurityTests`); new code paths
  that touch secrets need a matching leak check.
- Fail closed: an unresolvable reference, unknown credential or broken allow-list refuses
  the request; it never passes traffic through unauthenticated.

## Layout

```
src/CredProx.Abstractions/   plugin contract (stages, providers, sources) — no dependencies
src/CredProx/                core + built-in features
src/CredProx.AzureKeyVault/  add-on: Key Vault secret source, TokenCredential
src/CredProx.Testing/        fakes + conformance suites for plugin authors
tests/…                      see the table above
samples/                     E1–E14 (plan §6) — examples are the main documentation
```

## Adding a vendor

The library ships **no built-in vendor presets** (0.4.0): every vendor lives in its own
isolated sample — README, explicit config, WireMock stubs where it runs offline, smoke
script. To add one:

1. Create `samples/<Vendor>` modeled on the closest existing sample (E4 Spotify is the
   smallest OAuth client-credentials shape; E12 LoginExchange shows partitions and the
   allow-list). Write the credential block out in full — no preset references.
2. Add it to `CredProx.slnx` and the CI sample build loop
   (`.github/workflows/ci.yml`), plus a smoke step if it runs offline.
3. A preset is a **distribution** choice for preset authors, not a library feature:
   package fixed vendor facts (token endpoint, client-auth style, response shape,
   conventional `secret:` name) as `CredProx:Presets` config or a custom `IPresetSource`
   in your own package. Everything tenant- or app-specific stays with the host, and every
   preset field can be overridden field by field. A preset must never introduce a secret
   reference the host has to guess: name the conventional `secret:` reference and
   document the required host fields.

## Writing a credential-type plugin

The contract is `ICredentialProvider` in `CredProx.Abstractions`; registration is
explicit (`AddCredProx` options), never convention-scanned.

- **Template:** [`samples/CustomPlugin`](samples/CustomPlugin) — a complete custom
  credential type in ~50 lines with its test suite.
- Test it with the `CredProx.Testing` conformance suites (`FakeUpstream`,
  `FakeTokenServer`, `CapturedLogSink`) so your plugin proves the same secret-hygiene and
  refresh behaviour the built-ins do.
- Keep secrets inside your provider: request them through `ISecretAccessor`, never log
  them, and return failures as names/reasons only.

## Pull requests

- One change per PR; describe the behaviour it promises and the tests that pin it.
- CI runs build, all suites, coverage gates and the offline samples. Samples build against
  the **packed `.nupkg`**, so packaging mistakes fail CI too.
- Security-sensitive changes (token cache, secret scoping, allow-lists, caller auth,
  signing) get an explicit review pass against the boundaries listed in
  [SECURITY.md](SECURITY.md).
