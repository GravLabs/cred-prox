# Publishing CredProx

The release runbook. **Publishing is deliberately not automated**: no CI job pushes
packages, and pushing a tag does not publish anything. The person approves each publish
(plan §9 decision 3: the CredProx NuGet registry only; nuget.org postponed).

**Two homes since M25.** `https://github.com/GravLabs/cred-prox` is the canonical source
home: package metadata, SourceLink, issues and contribution links all point there. The
**package registry is a machine-local feed** — publishing machines declare it as the
`credprox` source (URL and push token) in their **user-level** NuGet config, never in the
repo tree. This runbook deliberately does not print the registry URL: resolve it from the
`credprox` source on the publishing machine.

Current state (2026-10-30): `0.7.0` is **published to the registry** (`main` and tag
`0.7.0` at `9391b1a` on the internal remote). The GitHub launch — one squashed
clean-start commit of the post-M25 tree plus the `0.7.0` tag — is cut and pushed by the
architect only on the person's explicit word. After the launch, the next release's
packages will carry GitHub SourceLink/metadata; `0.7.0` as published carries the
historical internal-source metadata.

## What gets published

Four packages and their symbol packages, all at the same version:

`CredProx` · `CredProx.Abstractions` · `CredProx.AzureKeyVault` · `CredProx.Testing`

Feed: the `credprox` source from machine-local NuGet config (anonymous download live).

## Prerequisites checklist

1. **`main` is at the release commit and CI is green** on it (build, all suites,
   coverage gates, example smokes, vulnerable-dependency scan, SourceLink assertion).
   Until the GitHub launch, Actions does not run for this tree — run that same gate
   battery locally on the release commit and say so (see Release history).
2. **The registry answers** from the publishing machine (that is where the `credprox`
   URL resolves). If the registry listener is down at publish time, every consumer's
   restore breaks; SourceLink now resolves to GitHub, so debugger source is unaffected.
3. **A publishing API key** for the registry account, kept in the user-level NuGet
   config keyed by the `credprox` source name. Keep it out of the repo.
4. **The release tag exists**: `git tag <version> <release-commit>` — pushing the tag
   needs the person's explicit OK, like any push.
5. **The baseline folder is current**: `build/baselines/` holds the *previously
   published* version's four nupkgs (see Rules and ADR-0001).

## Publish steps

Pack **with CI-equivalent path mapping** — a plain local pack embeds the builder's
source root in the PDB; the published PDB must carry `/_/` paths:

```bash
dotnet pack src/CredProx.Abstractions -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
dotnet pack src/CredProx              -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
dotnet pack src/CredProx.AzureKeyVault -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
dotnet pack src/CredProx.Testing      -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
```

Packing also runs the APICompat baseline check against `build/baselines` — it must exit 0.

Sanity-check the symbols before pushing (the CI step asserts the same on every build):

```bash
for pkg in artifacts/publish/*.snupkg; do
  unzip -p "$pkg" 'lib/net10.0/*.pdb' | grep -aq 'https://raw.githubusercontent.com/GravLabs/cred-prox/' \
    || { echo "SourceLink missing: $pkg"; exit 1; }
done
```

Push each **`.nupkg`** — the client automatically pushes the adjacent `.snupkg`
along with it (routed to the registry's `symbolpackage` endpoint; every PUT should
answer `201 Created`). Pushing the `.snupkg` files separately afterwards answers
`409 Conflict` — harmless (the symbol is already there) but confusing; don't.
A quoted `"*upkg"` glob is **not** expanded by `dotnet nuget push` (0.4.0 proved:
"File does not exist") — loop over the nupkgs instead. The registry source needs
`allowInsecureConnections="true"` if it serves plain HTTP — declare it machine-local.

```bash
for f in artifacts/publish/*.nupkg; do
  dotnet nuget push "$f" --source credprox
done
```

## Verify as a consumer

In a scratch project (isolated package cache and cleared http-cache prove the download,
not a cache hit):

```bash
dotnet nuget locals http-cache --clear
dotnet add package CredProx -v <version>   # credprox source from machine-local config
```

Then run `samples/QuickStart` against the feed (it already restores from packages) and,
with a debugger attached, step into a CredProx call — SourceLink should fetch the exact
release source from GitHub.

If a restore right after publish answers `NU1102` (version not found) although the
registry serves the new version, the local NuGet **http-cache** still holds the
pre-publish version listing — the 0.6.0 release proved it. Clear it and retry:

```bash
dotnet nuget locals http-cache --clear
```

## Rules

- **Versions are immutable** on the registry: never repack a published version; bump
  forward. (Locally, repacking the same version needs the NuGet global-cache folder for
  that version evicted first, or samples silently run the old extraction.)
- **Baseline rotation each release** (ADR-0001): after publishing `<new>`, the next
  milestone sets `<PackageValidationBaselineVersion>` in `Directory.Build.props` to
  `<new>` and replaces `build/baselines/` with the four nupkgs **downloaded from the
  registry** (the published bytes), updating the sha256 list in ADR-0001. Because the
  baseline is a committed file, the stale-global-cache failure that twice masked real
  breaks pre-M25 is structurally gone; the review duty moved to the diff — baseline
  bytes only ever change in an explicit rotation commit.
- SDK 10.0's APICompat has **no `[Experimental]` awareness** — every baseline removal is
  CP0001, experimental or not (the experimental-stability downgrade landed in ApiCompat only
  after .NET 10; `ApiCompatExcludeAttributesFile` is not the lever — it feeds attribute
  comparison, and on newer SDKs listing `ExperimentalAttribute` there would disable
  that native skip). Intentional removals are recorded in the project's
  `CompatibilitySuppressions.xml` (SDK default path, auto-detected; regenerate with
  `dotnet pack /p:ApiCompatGenerateSuppressionFile=true`) — `src/CredProx` carries the
  two CP0002 entries for the intentional binary-level signature replacements
  (`CallerDefinition` ctor, `CredProxRequestState.AbortAsync`; see the CHANGELOG 0.5.0
  binary note). Pre-1.0 the CHANGELOG preamble is the consumer contract.
- A credential failure in the library answers `502` (§3.4) — the status codes in
  `README`/plan are the contract; changing one is a plan change, not a packaging fix.

## Release history

- `0.7.0` (`9391b1a`): published 2026-10-22 to the registry; consumer restore verified
  byte-identical against the pushed artifact (sha256 `8ef1b9ea…`). GitHub launch pending.
- `0.6.0` (`61dcca9`), `0.5.0`, `0.4.0`, `0.3.0`: published earlier releases, all on the
  registry; each was verified with a scratch-project consumer restore.
- Pre-M25, all source links and history pointed at the internal Gitea instance, and CI
  ran locally because that instance has no workflow runners registered (zero Actions
  runs across its history) — every release above was gated by the full local battery on
  the release commit.
