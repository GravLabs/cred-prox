# ADR-0001: PackageValidation baseline from committed packages

Date: 2026-10-30
Status: accepted (M25, GitHub public pivot)

## Context

Every `dotnet pack` runs APICompat against the last published release
(`<PackageValidationBaselineVersion>`, currently `0.15.1`) so a public-surface removal
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
build/baselines/CredProx.0.15.1.nupkg               dc062a5c892fddc37f1579d263cc8edd1a290f37e48121e8badf0b99038f29ab
build/baselines/CredProx.Abstractions.0.15.1.nupkg  2a412e57402a292566eeed505720567d13294656a4dc72003f29411e706a81f8
build/baselines/CredProx.Azure.0.15.1.nupkg         ad05b1412a6b62e8497edf46449f9852bf037552cfa9150749e3ff6964b5b8d7
build/baselines/CredProx.Identity.0.15.1.nupkg      587942e54d382a03754ecd81b481293dc2656cc54c72b4426937d37e73131aac
build/baselines/CredProx.Operations.0.15.1.nupkg    d16598f409bddf6d91ba409ce52668811bb15381ca9e165220ba7d21a0e8bc22
build/baselines/CredProx.Testing.0.15.1.nupkg       d179f261263b473cedd33dc3977c3239b5e374c2170016543b23621b80f47dfd
```

The files are the bytes downloaded from the registry that published them (sha256 above;
recorded here so a later audit can prove which bytes were blessed). `.gitignore` carries
one exception (`!build/baselines/*.nupkg`) for exactly these files. In the SDK, a
non-empty `PackageValidationBaselinePath` **skips the feed-based restore entirely**
(`Microsoft.NET.ApiCompat.targets`); the version property stays as the baseline identity
and the filename convention. Each release bumps the baseline to the previously published
version: download its published nupkgs from the registry (four through `0.11.0`, ten
from `0.12.0`, four from `0.14.0`, all six ids from `0.15.0` and `0.15.1`, the packages that keep their identity under ADR-0007), replace the folder, update this list.
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
at that commit. `0.14.0` rotated at the `0.15.0` prep (M49, 2026-11-21, owner word "yes do
this next for 0.15"): ADR-0007 retires six package ids, so four baselines remain — `CredProx`,
`CredProx.Abstractions`, `CredProx.Operations` and `CredProx.Testing`, the registry-served `0.14.0`
bytes, sha256 verified 4/4 equal to the published artifacts recorded in PUBLISHING.md's release
history. `CredProx.Identity` and `CredProx.Azure` are new ids and ship without a baseline. The
`0.13.1` set's entries are in git history at that commit. `0.15.0` rotated at the `0.15.1`
prep (2026-11-22, owner publish approval d-bd67e0f3 to the registry and GitHub): those
registry-served `0.15.0` bytes — all six, sha256 verified 6/6 equal to the published
artifacts recorded in PUBLISHING.md's release history — replace the `0.14.0` set, whose
entries are in git history at that commit. `CredProx.Identity` and `CredProx.Azure` now
carry published bytes, so all six packable ids validate against committed baselines and
the two baseline-less csproj overrides are gone. `0.15.1` rotated at the `0.15.2`
prep (2026-11-25, owner release approval d-9ce00ea4): those registry-served `0.15.1`
bytes — all six, sha256 verified 6/6 equal to the published artifacts recorded in
PUBLISHING.md's release history — replace the `0.15.0` set, whose entries are in git
history at that commit. Pack the
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
