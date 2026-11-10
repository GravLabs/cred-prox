# Publishing CredProx

The release runbook. **Publishing is deliberately not automated**: no CI job pushes
packages, and pushing a tag does not publish anything. The maintainer approves each publish
(plan §9 decision 3: the CredProx NuGet registry only; nuget.org postponed).

**Two homes since M25.** `https://github.com/GravLabs/cred-prox` is the canonical source
home: package metadata, SourceLink, issues and contribution links all point there. The
**package registry is a machine-local feed** — publishing machines declare it as the
`credprox` source (URL and push token) in their **user-level** NuGet config, never in the
repo tree. This runbook deliberately does not print the registry URL: resolve it from the
`credprox` source on the publishing machine.

Current state (2026-11-09): `0.9.1` is **published on the registry** — the patch on the
collapsed public line: a negative `expires_in` no longer parks the token cache (it is a
protocol violation: the token response is rejected through the unusable-response path,
nothing is cached, and the warning names the field and credential id but never the
value; `expires_in: 0` still falls back to `DefaultLifetime` with one warning per
credential), and the M33 soak/failure-injection harness plus its testing report are now
in the repository. GitHub `main` and tag `0.9.1` sit on **one squashed commit**
`c243c5fc97a73fda943e2bdab33778fe1c5f7d62` (noreply author; tree identical to the
internal release commit `92ee3a8`) appended on the previous public tip `db26705e` — a
regular append: no collapse, no tag deletions. CI green on the release commit
(Actions run 42646476058). `0.9.1` shipped end to end: packed once from the public
commit, each of the eight artifacts exactly once (the push client exits 0 without
printing response codes; pushes authenticate via the machine-local
`packageSourceCredentials` — an anonymous PUT answers 401 — and serving is proven
consumer-side), consumer restore byte-identical, QuickStart smoke green on the
downloaded bytes — its source links resolve to the publicly referenced commit
`c243c5fc`. `0.9.1` is the supported version; `0.9.0` and `0.8.2` source links still
resolve (both commits are publicly referenced). Source links for `0.8.1` and earlier
point at commits that are off every branch and tag; they resolve only while GitHub
retains the unreferenced objects (no support purge was requested) —
**unsupported-by-construction** (see the `0.8.1` history entry). The Entra
on-behalf-of removal shipped at `0.8.0` stays **breaking** for `Mode: EntraObo`
users, and the `0.9.0` https default stays breaking as described; both CHANGELOG
entries remain the consumer contract. The `0.7.1` known issues stay resolved (F1:
CI-path-mapped PDBs; F2: packed from a publicly resident commit); the `0.7.0`/`0.7.1`
published packages keep their historical metadata (immutable). The baseline rotation
**ran with the `0.9.2` prep**: `build/baselines/` holds the published `0.9.1` bytes
(sha256-verified; ADR-0001); the next rotation runs at the next release prep per the
rule below.

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
   needs the maintainer's explicit OK, like any push.
5. **The baseline folder is current**: `build/baselines/` holds the *previously
   published* version's four nupkgs (see Rules and ADR-0001).

6. **Benchmark regression pass (required since 2026-11-10):** on a quiet machine, run a
   full `tests/CredProx.Benchmarks` pass at the release commit and gate it with
   `scripts/bench-compare.sh` against the previous release's committed baseline
   (`tests/CredProx.Benchmarks/baselines/`); a FAIL blocks the release the same way
   a failed suite would, and after publishing, refresh the baseline folder per
   `docs/benchmarks.md`. On a shared machine this gate is in practice an allocation
   gate on the overhead suite — latency regressions are caught by the micro suites,
   and a same-run ratio below 1.0 is noise, not a win. Record the gate's summary line
   in the release history entry. There is no nightly benchmark run: timing on shared
   hardware is too noisy to gate on between releases.

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

Sanity-check the symbols before pushing (the CI step asserts the same on every build).
The path-form assertions are not decoration: `0.7.1` shipped with local build paths in
its PDBs because the ceremony packed reused obj without the CI property (see Release
history) — a silent degradation the byte-identical checks cannot see:

```bash
for pkg in artifacts/publish/*.snupkg; do
  paths=$(unzip -p "$pkg" 'lib/net10.0/*.pdb' | strings)
  grep -q 'https://raw.githubusercontent.com/GravLabs/cred-prox/' <<<"$paths" \
    || { echo "SourceLink missing: $pkg"; exit 1; }
  grep -q '/_/' <<<"$paths" \
    || { echo "PDB not CI-path-mapped (no /_/): $pkg"; exit 1; }
  grep -q "$HOME/" <<<"$paths" \
    && { echo "builder home embedded in PDB: $pkg - rebuild with ContinuousIntegrationBuild=true from clean obj"; exit 1; }
done
```

`ContinuousIntegrationBuild=true` maps paths at **compile** time: packing with
`--no-build`, or against obj reused from a plain build, silently embeds the local source
root even with the flag on the pack command. Rebuild the Release outputs with the
property (or start from clean `obj/`) before packing.

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
- **GitHub is a release mirror, not a history archive** (precedent set at `0.7.1`,
  2026-10-31; **history collapsed at `0.8.2`** per the decisions of 2026-11-05: "squash
  the github commits during the next push", "delete the tags"): with `0.8.2` the public
  line becomes **one commit with no parent**, built from the sanitized release tree;
  tags `0.7.0`/`0.7.1`/`0.8.0`/`0.8.1` are deleted from the public and `main` moves
  with `--force-with-lease`; the `0.8.2` annotated tag peels to the collapsed commit.
  Later releases add exactly **one squashed commit on top** (tree identical to the
  internal release commit) plus their tag, as before. Source links for `0.8.1` and
  earlier releases resolve only while GitHub retains the unreferenced commits —
  unsupported-by-construction. Never push internal history: the M25 clean-start
  guarantee means the public repo stays free of pre-launch internals, which is why the
  naive `git push --tags` route is structurally wrong here, not just untidy.
- **Baseline rotation each release** (ADR-0001): after publishing `<new>`, the next
  milestone sets `<PackageValidationBaselineVersion>` in `Directory.Build.props` to
  `<new>` and replaces `build/baselines/` with the four nupkgs **downloaded from the
  registry** (the published bytes), updating the sha256 list in ADR-0001.
  **Exception recorded 2026-11-04:** the `0.8.0` release shipped WITHOUT the rotation to
  `0.7.1` that was owed since that release — the served `0.7.1` bytes embed local builder
  PDB paths (F1 above) and committing them would be a new public disclosure; `0.7.1` was
  metadata-only so the `0.7.0` baseline validates the identical API. The rotation
  (skipped one generation) **ran at `0.8.1`** (2026-11-04) directly to the published
  `0.8.0` bytes — the owed `0.7.1` generation is subsumed: metadata-only, API identical
  to `0.7.0`, and superseded. See ADR-0001. A rotation must never be silent — it happens only with a
  note like this one in ADR-0001. Because the
  baseline is a committed file, the stale-global-cache failure that twice masked real
  breaks pre-M25 is structurally gone; the review duty moved to the diff — baseline
  bytes only ever change in an explicit rotation commit.
- SDK 10.0's APICompat has **no `[Experimental]` awareness** — every baseline removal bites,
  experimental or not (CP0001 for a removed type, CP0002 for a removed member; the
  experimental-stability downgrade landed in ApiCompat only
  after .NET 10; `ApiCompatExcludeAttributesFile` is not the lever — it feeds attribute
  comparison, and on newer SDKs listing `ExperimentalAttribute` there would disable
  that native skip). Intentional removals are recorded in the project's
  `CompatibilitySuppressions.xml` (SDK default path, auto-detected; regenerate with
  `dotnet pack /p:ApiCompatGenerateSuppressionFile=true`) — as of `0.8.1` the file is
  **deleted**: every historical intentional removal (the 0.4.0 preset, the 0.5.0
  binary-level signature replacements, the 0.8.0 EntraObo removal) is already inside the
  current `0.8.1` baseline, so no suppression can fire; a fresh-obj pack must show zero
  diagnostics **and** zero unnecessary-suppression warnings. Pre-1.0 the CHANGELOG
  preamble is the consumer contract.
- A credential failure in the library answers `502` (§3.4) — the status codes in
  `README`/plan are the contract; changing one is a plan change, not a packaging fix.

## Release history

- `0.9.1` (GitHub `c243c5fc97a73fda943e2bdab33778fe1c5f7d62`, internal release commit
  `92ee3a8`): published 2026-11-09 — patch release. A negative `expires_in` (number or
  numeric string) is now rejected as a protocol violation through the unusable-response
  path — nothing is cached and the warning names the field and credential id, never the
  value or token — so a token already expired at mint time no longer parks in the cache
  for up to an hour of guaranteed-rejected upstream calls; `expires_in: 0` still falls
  back to `DefaultLifetime` with one warning per credential. Adds the soak and
  failure-injection harness with its testing report to the repository (docs and
  tooling beyond the library fix). Public history: ONE squashed commit on the previous
  public tip, noreply identity — a regular append, no collapse, no tag deletions; CI
  green (Actions run 42646476058). Ceremony: packed **once** from a clean detached
  worktree at the PUBLIC commit after tree equality with the reviewed `92ee3a8`,
  `-p:ContinuousIntegrationBuild=true` from fresh obj into an isolated package cache;
  sanity loop ×4 passed (SourceLink carries the full public SHA and the `/_/*`-to-raw
  mapping in every symbol package; no builder-home paths in any pdb or dll); APICompat
  against the rotated `0.9.0` baselines exit 0, additive surface only; extended
  disclosure scan over every member of all eight packages (49 members incl all eight
  `*Content_Types*` members) zero hits, exit code captured without a pipe tail. The
  push round: four nupkgs (the client auto-routes the adjacent snupkgs), each version
  exactly once — pushes authenticate via the machine-local `packageSourceCredentials`,
  serving proven consumer-side. Nupkg sha256: `CredProx`
  `1fddac05fe93db2df8fd5aba1d4b925dce1596c907e989117e96f60aad84459c`,
  `CredProx.Abstractions`
  `3a2c27b3508ea998f885d197eff1b0cf9622e77bbb7989bdd4bbe56acb050012`,
  `CredProx.AzureKeyVault`
  `deefdc0e349074b8deba234cff5ffa89e23b9fdd2ac08a2af20c834ac4d67a55`,
  `CredProx.Testing`
  `56a018db98fec850a60d031bc1f373f33dcc4a71915ac55e09e97317bdfd3c71`. Consumer verify:
  http-cache cleared, out-of-repo scratch project (the repo-level source mapping pins
  `CredProx*` to the local feed, so an in-tree restore cannot prove the registry),
  isolated package cache, all four downloads byte-identical to the pushed artifacts,
  `samples/QuickStart` smoke green on those exact bytes (WireMock journal shows the
  credential attached; the caller's echo shows it redacted). Review: fresh-context
  review PASS at the prep commit `76b2ba8`; two text-only NANO findings folded into the
  release commit before publish.
- `0.9.0` (GitHub `db26705e040ddddd3cabef748ea6964196eda4be`, internal release commit
  `a1c5e78`): published 2026-11-08 — **BREAKING**, the first on the collapsed line:
  `RequireHttpsMetadata` (default `true`) now governs the authority-discovery and
  direct-JWKS fetches that carry the keys validating inbound tokens; http `JwksUri`
  configurations (which worked before) must set `RequireHttpsMetadata: false` or fail
  at startup, and http `Authority` configurations (which already failed every request
  at runtime) get the same clear startup message or the opt-out. The metadata fetch
  rides the per-connection egress client; the direct JWKS cache is keyed by posture.
  Ships the accepted M31 token-lifecycle hardening (credential attachment refuses
  empty values, restricted names, and BCL-parsed names before the request leaves the
  proxy; JWT assertion certificate failures unified into one clear load error) and
  the M32 consumer-compatibility guide and script. Public history: ONE squashed
  commit on the previous public tip, noreply identity — a regular append, no
  collapse, no tag deletions; CI green (Actions run 42485303537). Ceremony: packed
  **once** from a clean detached worktree at the PUBLIC commit after tree equality
  with the reviewed `a1c5e78`, `-p:ContinuousIntegrationBuild=true` from fresh obj
  into an isolated package cache; sanity loop ×4 passed (SourceLink carries the full
  public SHA and the `/_/*`-to-raw mapping; no builder-home paths in any pdb or dll);
  APICompat against the rotated `0.8.2` baselines exit 0, additive surface only;
  extended disclosure scan over every member of all eight packages (49 members incl
  all eight `*Content_Types*` members) zero hits, exit code captured without a pipe
  tail. The push round: four nupkgs (the client auto-routes the adjacent snupkgs),
  each version exactly once — pushes authenticate via the machine-local
  `packageSourceCredentials` (anonymous PUT answers 401), so the client's
  missing-API-key notice is benign and serving is proven consumer-side. Nupkg sha256:
  `CredProx` `a3a599ffc4dd00b944a210d43c34aae20adb066111696c5fcece5bec9f4d62e2`,
  `CredProx.Abstractions`
  `c8e07c260a9bb0351bbd8ed3c946f5d4341f2f371447136ce4dcb6adac929c7e`,
  `CredProx.AzureKeyVault`
  `4edd4e5e178157e2adfac89755829ad5c8dad861dbdb158271c3b0b356c371c2`,
  `CredProx.Testing`
  `ce18a0591e0c804a4cd1adfe1fe9625d91737d8604e385df5be8a7defb424c6a`. Consumer verify:
  http-cache cleared, out-of-repo scratch project (the repo-level source mapping pins
  `CredProx*` to the local feed, so an in-tree restore cannot prove the registry),
  isolated package cache, all four downloads byte-identical to the pushed artifacts,
  `samples/QuickStart` smoke green on those exact bytes (WireMock journal shows the
  credential attached; the caller's echo shows it redacted). Independent registry
  re-check: 4/4 sha256 match, zero disclosure hits, nuspec commit `db26705`, raw
  source URL answers 200. Review: fresh-context spot-check PASS at the internal tip
  `a1c5e78` (no findings).
- `0.8.2` (GitHub `4f663ac90d14dfbd048a008b9379ebd88a592dcd`, internal release commit
  `ec79b35`): published 2026-11-07 — **library code unchanged from `0.8.1`** (the only
  in-package content change is the AzureKeyVault README docs); ships via the tree the
  M28 vendor config snippets, the M29 Azure live round-2 tooling, sample and validation
  report, and the Azure Container Apps sample. First release on the **collapsed public
  line** (decided 2026-11-05): ONE root commit (no parent) was built
  from the sanitized release tree with the noreply identity, audited a fresh object set,
  moved `main` with `--force-with-lease`, deleted the public tags `0.7.0`/`0.7.1`/
  `0.8.0`/`0.8.1` and tagged `0.8.2` on the collapsed commit; CI green (Actions run
  42320666021). Ceremony: packed **once** from a clean detached worktree at the PUBLIC
  commit (SourceLink embeds the pack-time HEAD — provenance rule), tree equality with
  the reviewed `ec79b35` verified first, `-p:ContinuousIntegrationBuild=true` from fresh
  obj into an isolated package cache with `ValidatePackage.semaphore` swept; sanity loop
  ×4 passed (SourceLink carries the full public SHA, `/_/`-mapped PDBs, no builder-home
  paths); APICompat against the rotated `0.8.1` baselines green; extended disclosure scan
  over every member of all eight packages (incl the `*Content_Types*` glob) zero hits.
  Registry state after the single push round: all eight artifacts present, each version
  exactly once (non-2xx would have raised — it did not). Nupkg sha256: `CredProx`
  `14d6044a598ab043cf9468dcabf9deb9d1e3e326b4ef5c6741edf3d727a87b6f`,
  `CredProx.Abstractions`
  `f4cdd0f87946d4c03ba6f267f0ac311539eea8419b1c8c411a0f39c9b1cf9b40`,
  `CredProx.AzureKeyVault`
  `0459800055597ad0ebd5ce3ac8484f979b559b3926fe1ce1d5c1a52a51a27ff2`,
  `CredProx.Testing`
  `6b414927800a9438b952c785e7aef0b8a0536b354a46bc1a973b51bba8115342`. Consumer verify:
  http-cache cleared, out-of-repo scratch project (the repo-level source mapping pins
  `CredProx*` to the local feed, so an in-tree restore cannot prove the registry),
  isolated package cache, all four downloads byte-identical to the pushed artifacts,
  `samples/QuickStart` smoke green on the downloaded bytes (WireMock journal shows the
  credential attached; the caller's echo shows it redacted). Independent registry
  independent re-check: 4/4 sha256 match, zero disclosure hits, nuspec commit
  `4f663ac9`, raw source URL answers 200. Review: fresh-context spot-check PASS at the
  internal tip `ec79b35` (docs coherent, baseline provenance closed on three independent
  sources, reviewer-runs battery green, real APICompat re-validation).
- `0.8.1` (GitHub `48140d51ea1c2b0f4126c33128b27378751f0238`, internal release commit
  `78a65ad`): published 2026-11-04 — the **same code and API as `0.8.0`, repacked from
  the rewritten public history** (decided: full scrub of the internal hostname
  found in pre-`0.8.0` committed baseline nuspecs and one prose mention; GitHub noreply
  authoring). The public line was rebuilt from sanitized trees: `main` and the
  annotated `0.8.1` tag (tag object `8d0e85f7`) at `48140d51`, tags `0.7.0`→`de3a34e8`,
  `0.7.1`→`9f9a8910`, `0.8.0`→`beb080e8` (objects `7e0064f2`/`2a577437`/`8e129586`),
  original dates kept, noreply author/committer/tagger; a fresh-clone audit of the whole
  public history answered zero disclosure hits; CI green (Actions run 41903045364).
  Ceremony: packed **once** from a clean detached worktree at `48140d51` after tree
  equality with the reviewed `78a65ad` was verified, `-p:ContinuousIntegrationBuild=true`
  from fresh obj into an isolated package cache; hardened sanity loop ×4 passed (GitHub
  SourceLink containing the full new commit SHA, `/_/` path-mapped PDBs, no builder-home
  paths); APICompat against the rotated `0.8.0` baselines: zero diagnostics, zero
  unnecessary-suppression warnings (suppressions file deleted; `ValidatePackage.semaphore`
  ×4); extended disclosure scan over every member of all eight packages clean with full
  byte coverage (member loop incl the `*Content_Types*` glob). All eight pushes answered
  `201 Created`, each package exactly once. Nupkg sha256: `CredProx`
  `f8cd3415fb1e228920233f6b29bf7d1d6905d0d7e0c2bf7396818a6ae8f2bcf6`,
  `CredProx.Abstractions`
  `f3703d687bcb1e7eed17102f921752fbb369d1b29bbe8254098d5690003fbfc4`,
  `CredProx.AzureKeyVault`
  `e6bd305e5d93f913a463f78efead83f5a357c24541134988ac61d44b2c8e6bab`,
  `CredProx.Testing`
  `ed232aef8acaf343c35b7df70ee6f451ead0f491e0374f80152562ab01e575ec`. Consumer verify:
  http-cache cleared, out-of-repo scratch project (the repo-level source mapping pins
  `CredProx*` to the local feed, so an in-tree restore cannot prove the registry),
  isolated package cache, all four downloads byte-identical to the pushed artifacts,
  `samples/QuickStart --smoke` green on the downloaded bytes.
- `0.8.0` (`dc8b984`): published 2026-11-04 to the registry — packed **from the GitHub
  mirror commit** `2d036703d21dee7fe1660ed83deea82dcdcd1686` (squashed, parent `cdcb823`,
  tree identical to `dc8b984`) after CI green on it (Actions run 41888135158), then
  `-p:ContinuousIntegrationBuild=true` from a clean worktree; all eight pushes answered
  `201 Created`. Ships the M27 Entra on-behalf-of removal (breaking; CHANGELOG is the
  contract) plus the M26 live-validation tooling and docs (zero `src/` delta). Nupkg
  sha256: `CredProx`
  `ff1e057a6f8657aa6993aa777f61daf1cac24905c065f0e16893eaf43e5d1258`,
  `CredProx.Abstractions`
  `d51ab22174ae539eb28bfbba856b391dce47df9c7c2b865916ac8cbf3f8d2ef5`,
  `CredProx.AzureKeyVault`
  `16e1c4fc8138819e2db783659c435e46a3115e462660780d0ca4a74bdf3286a2`,
  `CredProx.Testing`
  `d59a3dbe63dd65e9731b6ad53cc789fa1dee51927ca5f88708dcb5f0e3f33bef`. Consumer verify:
  http-cache cleared, out-of-repo scratch project (the repo-level source mapping pins
  `CredProx*` to the local feed, so an in-tree restore cannot prove the registry),
  isolated package cache, all four downloads byte-identical to the pushed artifacts,
  `samples/QuickStart --smoke` green on the downloaded bytes. **F1 resolved:** the hardened
  sanity loop passed on all four symbol packages — GitHub SourceLink present, `/_/`
  path-mapped, no builder-home paths. **F2 resolved:** SourceLink names the publicly
  resident `2d036703` and the raw URL answers 200, so released source is externally
  step-able. Extended disclosure scan (builder-path and internal-host patterns, every
  member of all eight packages) clean. APICompat green against the frozen `0.7.0`
  baselines; the `0.7.1` baseline rotation was **skipped** with reasons recorded in
  ADR-0001 (the served `0.7.1` bytes embed builder-local PDB paths — committing them
  would be new disclosure; metadata-only release, API identical to `0.7.0`).
  **Post-release:** the 2026-11-04 public-history rewrite (internal-hostname scrub,
  decision) takes mirror commit `2d036703` off every branch and tag. This
  release's source links resolve only while GitHub retains the unreferenced commit —
  no support purge was requested, and the raw URL still answered 200 at rewrite time —
  so the links are unsupported-by-construction, not broken today. `0.8.1` repacks the
  same code from the rewritten clean tip, so its consumers get source that resolves to
  a publicly referenced commit.
- `0.7.1` (`4d158ff`): published 2026-10-31 to the registry and mirrored to GitHub (one
  squashed commit `cdcb823` + annotated tag, CI green — the mirror precedent above);
  metadata-only repack of the `0.7.0` sources — GitHub URLs + GitHub SourceLink in nuspec/PDBs, and the inter-family
  nuspec dependencies moving `0.7.0`→`0.7.1` (mechanical: a ProjectReference dependency
  follows the package version — **not** drift). Baseline rotation to the published
  `0.7.0` bytes (ADR-0001). Consumer restore verified byte-identical (sha256
  `d418132f…`); all four APICompat gates green on fresh obj. Provenance note: the packed
  artifacts embed commit `726b5e4` (the release tree was packed just before its commit;
  content is identical to `4d158ff`). **Known issue (F1, found post-publish by review):**
  all four served `0.7.1` symbol packages embed the builder's local source paths instead
  of normalised `/_/` paths — the ceremony packed reused obj compiled without
  `ContinuousIntegrationBuild` (the flag maps paths at compile time; see the note under
  Publish steps). Independently confirmed: served PDBs `/…/home/`-present, `/_/`-absent,
  4/4; the `0.7.0` served bytes are correct. No secret content; byte-identical checks
  cannot see it. Immutable — forward-fixed at the next release via the hardened sanity
  loop and the compile-time note.
- `0.7.0` (`9391b1a`): published 2026-10-22 to the registry; consumer restore verified
  byte-identical against the pushed artifact (sha256 `8ef1b9ea…`). Superseded on the
  registry by `0.7.1` (metadata-only); now the committed APICompat baseline (ADR-0001).
- `0.6.0` (`61dcca9`), `0.5.0`, `0.4.0`, `0.3.0`: published earlier releases, all on the
  registry; each was verified with a scratch-project consumer restore.
- Pre-M25, all source links and history pointed at the internal repository, and CI
  ran locally because that instance has no workflow runners registered (zero Actions
  runs across its history) — every release above was gated by the full local battery on
  the release commit.
