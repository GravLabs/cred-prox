# ADR-0001: PackageValidation baseline from committed packages

Date: 2026-10-30
Status: accepted (M25, GitHub public pivot)

## Context

Every `dotnet pack` runs APICompat against the last published release
(`<PackageValidationBaselineVersion>`, currently `0.13.1`) so a public-surface removal
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
build/baselines/CredProx.0.13.1.nupkg               740dc87f35af29cc59c3349deb2f350df76bd218c4ad5a723f661650223e30c6
build/baselines/CredProx.Abstractions.0.13.1.nupkg  569d42bd100946993272b34e17ed04f248af1788a1acba720577ffa7c9c2caa3
build/baselines/CredProx.AzureKeyVault.0.13.1.nupkg b45fe46c942db33e6ef9e98572f28866fae7451dd30a68100d659ecfb267a9e8
build/baselines/CredProx.CallerKeys.0.13.1.nupkg    ed85f747f9550cfcda2c8e6d9d079b60eeee2842556681815d06d2c9ae8cb001
build/baselines/CredProx.CallerTokens.0.13.1.nupkg  5ec9a232d6273aa456e9d03e0c42594a9d741d6d4fcfe84e825babe226ea1551
build/baselines/CredProx.Hmac.0.13.1.nupkg          5ea460ef2cb1efeffeca58ece6c7707f1ccaabadfe7a079f4bc5b683b8856d2d
build/baselines/CredProx.LoginExchange.0.13.1.nupkg 17143d012c4e62ab5c1db42d56aa213c69ca3221bcc5793028ce76c5f83acc8f
build/baselines/CredProx.OAuth.0.13.1.nupkg         9235ca2197b5e174ec6e40b821de0d3d60145b7e86d90246abf07a5072cbefd1
build/baselines/CredProx.Operations.0.13.1.nupkg    95fdbdef11a5b679705a5c624e8e8a9522ceae08db8b891241f394886dfefa9e
build/baselines/CredProx.Testing.0.13.1.nupkg       fe1f33a6221cb0f269be6ca92c2c9cac0a3ba72f8197f6315c30c3bc2bf1eb9e
```

The files are the bytes downloaded from the registry that published them (sha256 above;
recorded here so a later audit can prove which bytes were blessed). `.gitignore` carries
one exception (`!build/baselines/*.nupkg`) for exactly these files. In the SDK, a
non-empty `PackageValidationBaselinePath` **skips the feed-based restore entirely**
(`Microsoft.NET.ApiCompat.targets`); the version property stays as the baseline identity
and the filename convention. Each release bumps the baseline to the previously published
version: download its published nupkgs from the registry (four through `0.11.0`, ten
from `0.12.0`), replace the folder, update this list.
Rotations executed: `0.6.0` at M25 (2026-10-30, hashes in git history at that commit);
`0.7.0` for the 0.7.1 metadata release (2026-10-30; hashes in git history at that
commit). `0.7.1` **deliberately skipped** for the 0.8.0 release (2026-11-04, release
decision on the maintainer's go-ahead): the owed rotation to `0.7.1` would have committed
registry bytes whose DLLs/PDBs embed the builder's absolute local source path instead of
`/_/` (the F1 known issue in PUBLISHING.md's release history) — committing them would
have been NEW public disclosure, and `0.7.1` was metadata-only, so the `0.7.0` baseline
already validated the identical API. `0.8.0` rotated at `0.8.1` (2026-11-04, maintainer
full-scrub decision — that generation's entries, the registry-served `0.8.0` bytes
each sha256-verified during the 0.8.0 consumer restore, are in git history at that
commit), and the skipped `0.7.1` generation is subsumed — superseded, API identical to
`0.7.0`. `0.8.1` rotated at `0.8.2` (2026-11-07, maintainer release go-ahead "merge and publish
when ready"): those registry-served `0.8.1` bytes — sha256
verified equal to the published artifacts recorded in PUBLISHING.md's release history,
and disclosure-scanned member-by-member before commit (zero hits) — are in git history
at that commit. The `0.8.2` rotation also removed the last disclosure residual of the `0.7.0` set: their
nuspec `RepositoryUrl` carried the internal registry URL (public since the launch commits,
prose since scrubbed) — the `0.8.0` nuspecs carry the GitHub URL, so the current tree is
clean. `0.9.0` rotated at the `0.9.1` prep (2026-11-09, maintainer release go-ahead):
those registry-served `0.9.0` bytes — sha256 verified equal to the published artifacts
recorded in PUBLISHING.md's release history — replace the `0.8.2` set, whose entries are
in git history at that commit. `0.9.1` rotated at the `0.9.2` prep (2026-11-10,
maintainer release go-ahead): those registry-served `0.9.1` bytes — sha256 verified
equal to the published artifacts recorded in PUBLISHING.md's release history — replace
the `0.9.0` set, whose entries are in git history at that commit. `0.9.2` rotated at the
`0.9.3` prep (2026-11-11, maintainer release go-ahead d-0985b28a): those registry-served
`0.9.2` bytes — sha256 verified equal to the published artifacts recorded in
PUBLISHING.md's release history — replace the `0.9.1` set, whose entries are in git
history at that commit. `0.9.3` rotated at the `0.9.4` prep (2026-11-15, owner "your
call" ruling d-3cf81dc2 to publish M37 as a patch): those registry-served `0.9.3` bytes
— sha256 verified equal to the published artifacts recorded in PUBLISHING.md's release
history, and member-wise disclosure-scanned before commit (29 members, zero hits) —
replace the `0.9.2` set, whose entries are in git history at that commit. `0.9.4`
rotated at the `0.10.0` prep (2026-11-15, owner "1 yes" ruling d-f8dcadee to publish
M38 as a minor): those registry-served `0.9.4` bytes — sha256 verified equal to the
published artifacts recorded in PUBLISHING.md's release history, and member-wise
disclosure-scanned before commit — replace the `0.9.3` set, whose entries are in git
history at that commit. `0.10.0` rotated at the `0.11.0` prep (2026-11-16, owner
decision d-72cfeb67 to publish M39 and M40 as a minor): those registry-served `0.10.0`
bytes — sha256 verified equal to the published artifacts recorded in PUBLISHING.md's
release history — replace the `0.9.4` set, whose entries are in git history at that
commit. `0.11.0` rotated at the `0.12.0` prep (2026-11-17, owner approval of the 0.12.0
prep and publish): those registry-served `0.11.0` bytes — sha256 verified equal to the
published artifacts recorded in PUBLISHING.md's release history, and member-wise
disclosure-scanned before commit — replace the `0.10.0` set, whose entries are in git
history at that commit. `0.12.0` rotated at the `0.13.0` prep (2026-11-19, owner word
"1 0.13" naming `0.13.0` the next release): those registry-served `0.12.0` bytes — all
ten, sha256 verified 10/10 equal to the published artifacts recorded in PUBLISHING.md's
release history — replace the `0.11.0` set, whose entries are in git history at that
commit; the six feature packages join the folder, so every pack now validates all ten
packages against published bytes. `0.13.0` rotated at the `0.13.1` prep (2026-11-19,
owner word "A, registry now, nuget.org later"): those registry-served `0.13.0` bytes —
all ten, sha256 verified 10/10 equal to the published artifacts recorded in
PUBLISHING.md's release history — replace the `0.12.0` set, whose entries are in git
history at that commit. `0.13.1` rotated at the `0.14.0` prep (2026-11-20, owner word
"start 0.14.0 after the gpu-rig is done testing the engine"): those registry-served `0.13.1`
bytes — all ten, sha256 verified 10/10 equal to the published artifacts recorded in
PUBLISHING.md's release history — replace the `0.13.0` set, whose entries are in git history
at that commit. Pack the
**fresh**
`obj/` after rotating (see
Consequences): a repack on an untouched obj skips validation silently.

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
