# ADR-0001: PackageValidation baseline from committed packages

Date: 2026-10-30
Status: accepted (M25, GitHub public pivot)

## Context

Every `dotnet pack` runs APICompat against the last published release
(`<PackageValidationBaselineVersion>`, currently `0.6.0`) so a public-surface removal
fails the build before it can ship (PUBLISHING.md rules; the gate has caught real breaks).
Until M25 the baseline nupkg was **restored from a feed**: the repo's `NuGet.Config`
declared the internal LAN NuGet registry (anonymous download), and the SDK's
`PackageValidationBaselineVersion` support does a `PackageDownload` of that version.

M25 makes `https://github.com/GravLabs/cred-prox` the canonical source home. A public
tree cannot declare a LAN endpoint as a package source, and a GitHub-hosted runner has no
route to it — so the baseline restore had to stop depending on any feed.

## Decision

Commit the **published baseline packages** under `build/baselines/` and point
`<PackageValidationBaselinePath>` at them in `Directory.Build.props`:

```
build/baselines/CredProx.0.6.0.nupkg               da852b80c7a2b3cf229f0af01124abf3eaf3774b3b643e3e2f2232aad0620374
build/baselines/CredProx.Abstractions.0.6.0.nupkg  0beee8881c540ce3b9d8575500e628b15ac7543db1d1c555f740669317cf51ca
build/baselines/CredProx.AzureKeyVault.0.6.0.nupkg 9d907a318e7703797f6a14d12818e950c47fb23dec055dabe2b9e108272bf97a
build/baselines/CredProx.Testing.0.6.0.nupkg       160e6d754df18a0b2c6f0761babde87223bc0160c7f911418eafc7457b2f3464
```

The files are the bytes downloaded from the registry that published them (sha256 above;
recorded here so a later audit can prove which bytes were blessed). `.gitignore` carries
one exception (`!build/baselines/*.nupkg`) for exactly these files. In the SDK, a
non-empty `PackageValidationBaselinePath` **skips the feed-based restore entirely**
(`Microsoft.NET.ApiCompat.targets`); the version property stays as the baseline identity
and the filename convention. Each release bumps the baseline to the previously published
version: download its four nupkgs from the registry, replace the folder, update this list.

## Consequences

- Validation needs **no network and no LAN feed**: this machine and any GitHub-hosted
  runner compare against byte-identical baselines committed in the tree.
- The stale-baseline-cache failure mode that twice masked real breaks (PUBLISHING.md
  operational guard — a repacked local copy silently replacing the published baseline in
  the global cache) is **structurally gone**: there is no cache lookup to poison, and a
  wrong baseline byte changes the committed file, which is reviewable in the diff.
- Cost: ~250 KB of binaries in the repo per baseline generation, and one manual swap step
  per release (written into PUBLISHING.md).
- The repo-level `NuGet.Config` no longer declares the registry at all. Publishing
  machines keep the `credprox` source (and its token) in their **user-level** NuGet
  config; nothing outside this machine needs it.
- Validation is **incremental per `obj/` directory**: `RunPackageValidation`
  (`Microsoft.NET.ApiCompat.ValidatePackage.targets`) keys its incrementality on a
  semaphore under `obj/`, so within one `obj/` the gate runs on the first pack and every
  later repack with untouched inputs silently skips it. CI checkouts are always fresh, so
  the gate is structurally honest there — but a green local repack is **not** proof the
  gate ran. Reviewers and the baseline-rotation step must pack a fresh `obj/` (or delete
  `obj/**/*.ApiCompat.ValidatePackage.semaphore`) before trusting a local negative probe.

## Rejected options

- **Keep the LAN feed in the repo config.** Fails the pivot outright — a public tree must
  not carry a live internal endpoint, and a GitHub runner cannot reach it anyway.
- **Skip baseline validation when the feed is unreachable** (conditional property).
  A validation gate that silently disables itself off-LAN is worse than none: the break
  ships with a green build.
- **Publish the 0.x baselines to nuget.org.** Reopens a settled scope decision
  (plan §9 decision 3: nuget.org postponed); a release channel for old bits is more
  surface than a 250 KB folder.
- **`PackageDownload` with an explicit per-machine source name** (baseline restored from
  `credprox` only where declared). Still feed-dependent, still silently skippable, and
  keeps machine state on the critical path of a build gate.
