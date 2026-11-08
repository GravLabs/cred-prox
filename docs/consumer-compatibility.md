# Consumer compatibility

CredProx is consumed by applications that we do not build, with dependency
graphs we do not control. This page records what has been **measured from a
clean machine checkout** — separate scratch projects that reference only the
published packages (no project references, no repo `Directory.*.props`, no repo
`NuGet.Config`) — and what is deliberately not claimed.

Re-run everything with:

```bash
bash scripts/consumer-compat.sh            # all cells
bash scripts/consumer-compat.sh web drift  # selected cells
```

The script needs the .NET 10 SDK and Docker. It resolves CredProx packages
from the machine-local CredProx feed — declared as a source in the *user-level*
NuGet config on publishing machines. Its URL is never committed anywhere, and
the script itself references the source only by key (`credprox`). Each run uses
an isolated `NUGET_PACKAGES` cache under a scratch directory and clears the
per-run HTTP cache, so a published package can be re-verified the same day it
changes.

Results below were measured on 2026-11-07 against **CredProx 0.8.2**,
linux-x64, .NET SDK 10.0.114. Every smoke asserts the credential contract
end to end: the caller-side echo shows `[redacted]` while the raw credential is
proven vendor-side in the WireMock request journal.

## Results matrix

| Cell | Scenario | Result | Notes |
| --- | --- | --- | --- |
| web | minimal ASP.NET Core web app, `AddCredProx*` + config-loaded YARP route | pass | warning-clean under `-warnaserror`, no suppression needed |
| webapi | `dotnet new webapi` + controllers, CredProx route alongside them | pass | controllers keep working; run with `--no-launch-profile` or the profile's port overrides `ASPNETCORE_URLS` |
| auth | app with ASP.NET authentication + custom middleware in front of the proxy | pass | mount `MapReverseProxy` after `UseAuthentication`/`UseAuthorization`; middleware-set headers reach the upstream through the proxy |
| container | `dotnet publish /t:PublishContainer` + `docker run` | pass | tag gotcha: `ContainerImageTag` is tag-only (`CONTAINER2007`); the repo name goes in `ContainerImageName` |
| net8 | class library targeting `net8.0` adds the package | refuses, as designed | exact text below |
| net9 | class library targeting `net9.0` adds the package | refuses, as designed | exact text below |
| drift | CPM + `-warnaserror`: CredProx, CredProx.AzureKeyVault, latest `Yarp.ReverseProxy`, `Azure.Identity` 1.17.0 | pass | no `NU1605`; `Azure.Core` converges to a single 1.49.0 for both consumers — see drift notes |
| testing | xunit consumer project running `CredentialProviderConformanceTests<TProvider,TOptions>` | pass | needs `NoWarn` of `CREDPROX001` (the suite is `[Experimental]`) |
| trim | web app `PublishTrimmed` self-contained; console `PublishAot` | measured, **not supported** | see trimming section |

## Framework support

`net10.0` only. Older TFMs fail at restore with an exact diagnostic, e.g.:

```text
error NU1202: Package CredProx 0.8.2 is not compatible with net8.0 (.NETCoreApp,Version=v8.0). Package CredProx 0.8.2 supports: net10.0 (.NETCoreApp,Version=v10.0)
```

The same shape appears for `net9.0` and for the other three packages. This is
intentional: the credential pipeline uses .NET 10 APIs, and a restore-time
refusal beats a runtime surprise.

## Dependency drift

For a central-package-management consumer that treats warnings as errors, two
hygiene diagnostics fire before any conflict ever appears:

- `NU1507` — CPM refuses more than one package source unless sources are
  **mapped by key**. With a private CredProx feed plus nuget.org, the documented
  fix is a project-level `NuGet.config` mapping patterns to source keys; the
  keys come from the inherited configuration, so no URL ever enters the
  project:

  ```xml
  <configuration>
    <packageSourceMapping>
      <packageSource key="nuget.org"><package pattern="*" /></packageSource>
      <packageSource key="credprox"><package pattern="CredProx*" /></packageSource>
    </packageSourceMapping>
  </configuration>
  ```

- `NU1510` — on the net10 web SDK, explicit `PackageReference`s to
  `Microsoft.Extensions.*` packages that the framework already provides are
  flagged as unnecessary (transitive package pruning). Don't pin them
  explicitly; let the shared framework resolve them.

With those resolved, a drift project pinning the latest `Yarp.ReverseProxy` and
`Azure.Identity` 1.17.0 restores and builds warning-free. The Azure.Core
collision the Key Vault package is most likely to cause resolves cleanly:
`dotnet nuget why` shows a single `Azure.Core (v1.49.0)` reached through both
`Azure.Identity` and `CredProx.AzureKeyVault`, and no downgrade diagnostic
(`NU1605`) appears.

## CredProx.Testing from the outside

A consumer test project can verify its own `ICredentialProvider` implementation
against the same contract suite CredProx's built-ins pass:

- derive from `CredentialProviderConformanceTests<TProvider, TOptions>`;
- implement `CredentialTypeName`, `CredentialConfig` (keys relative to
  `CredProx:Credentials:conformance`, including `Type`) and `SecretValues`;
  override `SecretConfig` when the fixture secrets need values;
- the suite registers the provider type and a stub vendor HTTP pipeline
  (default 200 `{"access_token": …}`) automatically — a provider that logs in
  over HTTP drives it, e.g. via the `Failure_DoesNotLeakSecretValues` override;
- suppress exactly `CREDPROX001` (`NoWarn`) — the suite is `[Experimental]`
  like the plugin contract.

The whole matrix's `testing` cell is a working consumer example of this shape.

## Trimming and NativeAOT — not supported

Measured, and the answer is deliberately conservative:

- **Trimming:** a minimal web app using CredProx publishes self-contained with
  `PublishTrimmed=true`, but the linker summary reports
  `Assembly 'CredProx' produced trim warnings` (`IL2104`, attributed to
  `CredProx.dll`). No warning-free claim exists; trim warnings are not
  individually attributed in this matrix. **Trimmed or single-file
  deployments are not supported.**
- **NativeAOT:** a console probe rooting the CredProx entry-point types
  (`PublishAot`, linux-x64) compiles to a native binary with zero IL
  diagnostics **for that root set**. That is one probe against four entry
  points — not a whole-product claim. **NativeAOT is not supported.**

## Consumer-visible API notes

- The DI-based proxy setup (`AddCredProxTokenCache`,
  `AddCredProxConfigurationSecrets`, `AddCredProxBuiltInCredentials`,
  `AddCredProxCredentials`, `AddReverseProxy().…AddCredProx`) is
  warning-clean under `-warnaserror` with no suppression.
- Individual `[Experimental(CREDPROX001)]` surfaces — the conformance suite,
  and direct `typeof`/reflection on annotated marker types — require
  suppressing exactly `CREDPROX001`. Do not blanket-suppress.

## Not covered by this matrix

Windows and non-x64 targets; .NET 8/9 runtime hosting (refused at restore by
design, above); Blazor, gRPC and WebSocket proxy shapes; trimming/AOT
beyond the probes above (and the probes are entry-point-rooted, not full-API);
runtime behaviour of trimmed CredProx (not attempted — unsupported);
upgrade-drift between CredProx versions (matrix runs one published version at
a time).
