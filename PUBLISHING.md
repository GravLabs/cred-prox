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

Current state (2026-11-20): `0.13.1` is **published on the registry** — the security patch
for `0.13.0`: credential fetches refuse HTTP redirects, JSON-escaped credential echoes are
scrubbed, the scrubber's pass-through classes warn, and provider-boundary messages carry the
exception type only; no public API added, changed or removed. GitHub `main` and tag `0.13.1`
sit on one squashed commit `61b6ef8eeabc5660582e7b74cf91539fefc00cbe` (noreply author, tree
identical to the release tip `a8a700f`), appended on the previous public tip `4ac539b`; see
the `0.13.1` history entry. The baseline rotation to the published `0.13.1` bytes ran with
the `0.14.0` prep (ADR-0001). Previously: `0.13.0` was **published on the registry** — ten packages at
one version; it fixes caller-key rotation under upper-cased configuration sources (0.12.0
is affected), makes `CredProx:Health:Enabled=false` really off, removes the 0.12.0
per-request attach allocation, and documents how to replace or turn off each built-in
(ADR-0006). No public API was removed; package validation runs on all ten packages
against the published `0.12.0` bytes. GitHub `main` and tag `0.13.0` sit on one squashed
commit `4ac539bd5d00ae42fa11032a4f0d09294381b19e` (noreply author, tree identical to the
internal release commit `9b23040`), appended on the previous public tip `5cc1a7e`; see the
`0.13.0` history entry. Previously: `0.12.0` was **published on the registry** — the minimal core
with one package per optional feature (ADR-0005): **ten packages at one version**, six of
them (`CredProx.CallerKeys`, `CredProx.CallerTokens`, `CredProx.Hmac`,
`CredProx.LoginExchange`, `CredProx.OAuth`, `CredProx.Operations`) on the registry for the
first time. GitHub `main` and tag `0.12.0` sit on one squashed commit
`5cc1a7edbdd50c1ad66a89c002ea8a69f4eac90c` (noreply author, tree identical to the internal
release commit `682a676`), appended on the previous public tip `f239384`; see the `0.12.0`
history entry. The baseline rotation to the published `0.12.0` bytes ran with the
`0.13.0` prep (ADR-0001). Previously: `0.11.0` was **published on the registry** — the M39 agent tokens:
an agent presents a short-lived Microsoft Entra (or any OIDC) access token instead of a stored
secret, and Entra app roles narrow it to named rules — a token gets exactly the operations its
roles name, and a caller without named rules admits no token (sample E19 `samples/AgentTokens`;
ADR-0004). The caller-token API is additive; the one Breaking change is the caller contract
surface collapse — `CallerDefinition`, `CallerOperationRule` and `CallerIdentity` now carry
single constructors with optional parameters, migration is a recompile, and deconstructing a
`CallerIdentity` takes three variables (the CHANGELOG `[0.11.0]` Breaking entry is the consumer
contract; the four removed signatures are the 4 `CP0002` entries in the shipped
`CompatibilitySuppressions.xml` files — see the Rules section below). APICompat against the
published `0.10.0` surface is otherwise clean on all four packages. GitHub `main` and tag
`0.11.0` sit on **one squashed commit**
`f23938405d797f4dfc6564faaa7bdfb5dff2599a` (noreply author; tree identical to the internal
release commit `1fa3b6b`) appended on the previous public tip `3ba5264` — a regular append: no
collapse, no tag deletions; the annotated tag peels to that commit (the first tag object of this
release was replaced minutes after creation — see the `0.11.0` history entry). CI green on the
public commit (Actions run 43796995079, all three jobs). `0.11.0` shipped end to end: packed
once from the public commit (deterministic CI path mapping, fresh obj, isolated restore cache),
the four nupkgs pushed exactly once (the client auto-routes the adjacent snupkgs; pushes
authenticate via the machine-local `packageSourceCredentials` — an anonymous PUT answers 401 —
and serving is proven consumer-side), consumer restore byte-identical, QuickStart smoke green on
the downloaded bytes — the symbol packages carry the full public SHA `f239384` and the `/_/`
source mapping. `0.11.0` is the supported version; `0.10.0`, `0.9.4`, `0.9.3`, `0.9.2`, `0.9.1`,
`0.9.0` and `0.8.2` source links still resolve (their commits are publicly referenced). Source
links for `0.8.1` and earlier point at commits that are off every branch and tag; they resolve
only while GitHub retains the unreferenced objects (no support purge was requested) —
**unsupported-by-construction** (see the `0.8.1` history entry). The Entra on-behalf-of removal
shipped at `0.8.0` stays **breaking** for `Mode: EntraObo` users, the `0.9.0` https default
stays breaking as described, the `0.11.0` caller contract collapse is the third breaking
change, recompile-only as the CHANGELOG describes it, and the `0.12.0` package split is the
fourth: binary-breaking for hosts that reference moved types (recompile against the core
plus the feature package), additive for everyone else — the CHANGELOG `[0.12.0]` Breaking
entries are that contract; the CHANGELOG entries remain the consumer
contract. The `0.7.1` known issues stay resolved (F1: CI-path-mapped PDBs; F2: packed from a
publicly resident commit); the `0.7.0`/`0.7.1` published packages keep their historical
metadata (immutable). The latest baseline rotation **ran with the `0.14.0` prep**: `build/baselines/`
holds the published `0.13.1` bytes (all ten, sha256-verified; ADR-0001); every pack
validates all ten packages against them; the next rotation runs at the next release prep
per the rule below.

## What gets published

Ten packages and their symbol packages, all at the same version:

`CredProx` · `CredProx.Abstractions` · `CredProx.AzureKeyVault` · `CredProx.CallerTokens` · `CredProx.CallerKeys` · `CredProx.Hmac` · `CredProx.LoginExchange` · `CredProx.OAuth` · `CredProx.Operations` · `CredProx.Testing`

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
   published* version's nupkgs — four through `0.10.0`, six from the release that
   first ships `CredProx.CallerTokens` and `CredProx.CallerKeys` together, eight
   from the release that also ships `CredProx.Hmac` and `CredProx.LoginExchange`,
   nine from the release that also ships `CredProx.OAuth`, ten from the release that
   also ships `CredProx.Operations`
   (see Rules and ADR-0001).

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
dotnet pack src/CredProx.CallerTokens  -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
dotnet pack src/CredProx.CallerKeys    -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
dotnet pack src/CredProx.Hmac          -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
dotnet pack src/CredProx.LoginExchange -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
dotnet pack src/CredProx.OAuth         -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
dotnet pack src/CredProx.Operations    -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
dotnet pack src/CredProx.Testing      -c Release -o artifacts/publish -p:ContinuousIntegrationBuild=true
```

Packing also runs the APICompat baseline check against `build/baselines` — it must exit 0.
All ten packages validate: each package's own previously published bytes are its baseline,
and the six that first shipped at `0.12.0` entered that folder at the `0.13.0`-prep
rotation, where their temporary `EnablePackageValidation=false` overrides were removed.

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

## After publishing: reopen the dev line and evict the machine cache

Right after the last push, two actions on `main`:

1. **Reopen the version line.** Set `<Version>` in `build/Version.props` to
   `<next>-dev` (after the `0.13.0` publish: `0.14.0-dev`) and move the `CredProx*`
   pins in `Directory.Packages.props` with it. A plain released number left on
   `main` labels every later candidate pack with the published version id — the
   `0.12.0` development window produced ten `CredProx.0.12.0.nupkg` candidates and
   left the machine cache holding unreleased bytes under the released version id —
   so anything that resolves by version alone (a consumer-compat scratch, a
   byte-identity check against the published bytes) can silently take dev bytes
   for the release.
2. **Evict the machine cache for that id**, so the stale dir cannot serve again:

```bash
rm -rf ~/.nuget/packages/credprox*
```

   The next restore repopulates it from the registry — which now has the real
   published bytes under that id.

Do not add a test for the reopen: prep legitimately writes the plain number at
tag time, so no in-repo cell can tell prep-time plainness from post-publish
plainness. The two actions are ceremony steps, not gates.

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

## The nuget.org route (parallel to the registry route)

The registry route above stays the default until the owner opens the nuget.org account.
Everything below is the whole delta for publishing to nuget.org; the pack commands, the
CI-path-mapping rule and the symbols sanity loop are shared with the registry route.

**Prerequisites unique to nuget.org:**

1. **The account and its API key.** A Microsoft-account-backed nuget.org account, then a
   **push-only API key** scoped by glob pattern to `CredProx*` and to the *Push*
   operation only (the scoping UI also offers "Push new packages and package versions",
   "Push existing package versions only" and "Unlist" — a release key needs push, not
   unlist). Keep it where the registry key lives: the machine-local user-level NuGet
   config or the `NUGET_API_KEY` environment variable (NuGet 7.6 / SDK 10.0.300+),
   never in the repo.
2. **Prefix reservation.** Apply for the `CredProx` prefix (it covers the `CredProx.*`
   naming pattern) by emailing account@nuget.org with the owner display name, from the
   nuget.org account; the criteria are already met by the metadata audit
   (consistent author across the ten, `license` expression, no `licenseUrl`/`iconUrl`).
   This is the owner's action alongside the first publish — it grants the "reserved
   prefix" indicator, not publish permission.
3. **The version question** (see the M44 audit): if any packed byte changed since the
   `0.13.0` pack, the first nuget.org version is `0.13.1` — never a re-pack of the
   published `0.13.0` under the same id.

**Push loop** — same shape as the registry loop, explicit source, and the V3 endpoint is
required because symbol pushes only work over V3:

```bash
for f in artifacts/publish/*.nupkg; do
  dotnet nuget push "$f" --source https://api.nuget.org/v3/index.json --api-key "$NUGET_API_KEY"
done
```

**Snupkg delivery witness.** The adjacent `.snupkg` rides each nupkg push (same
auto-push as the registry route). nuget.org accepts only `.snupkg` symbols, via the V3
API; after validation the symbols are indexed at `https://symbols.nuget.org/download/symbols`.
Witness it as a consumer, not by trusting the push output: in the scratch project below,
attach a debugger and add that symbol source — stepping into a CredProx call must load
the `.pdb` from the symbol server and pull source from GitHub via SourceLink.

**Validation and indexing delay.** Every push runs nuget-side validations (virus check
among them); until they pass the package shows as **unlisted**, and indexing into search
then takes time — usually under 15 minutes, watch status.nuget.org if longer, and the
owner's account gets the success email. The consumer check below must therefore run
*after* the email, not right after the last push.

**Versions cannot be deleted, only unlisted** — the nuget.org Terms are explicit that
uploaded content cannot be guaranteed permanently deleted; unlisting hides the package
from search for new consumers while existing consumers keep resolving it. A bad version
is therefore permanent: unlist it and (if consumers should move) deprecate it pointing
at the replacement; forward-bump only. This makes the pack-identity rules above not
tidiness but irreversibility containment.

**Consumer check from a clean machine-shaped cache** — fresh `HOME`, fresh global
packages folder, so nothing can ride the publishing machine's cache:

```bash
export HOME=/tmp/m44-consumer-home   # fresh dir, no user-level config: nuget.org only
mkdir -p "$HOME"
dotnet new classlib -n M44Consumer -o m44-consumer && cd m44-consumer
dotnet add package CredProx -v <version>    # resolves from nuget.org alone
dotnet build
```

The M44 readiness gate pre-proved this exact route at pack time (isolated restore of
all ten packages against nuget.org alone, per-package provenance asserted from each
`.nupkg.metadata`); at publish time repeat it once, against the real feed.

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
- **Public tags are built, never inherited** (lesson from the `0.11.0` tag incident in
  the history entry): an annotated tag object's *tagger* is taken from the
  `GIT_COMMITTER_*` identity — setting `GIT_AUTHOR_*` alone does not cover it — and the
  object header keeps the refname the tag was created under, so a locally cross-named
  tag pushes a wrong header and a private identity. Build every public tag with
  `git mktag` from explicit text (noreply tagger, header exactly the release name),
  verify with `git cat-file -p` before the push (zero private-email hits, header exactly
  the release name), and never push a cross-named local tag.
- **Baseline rotation each release** (ADR-0001): after publishing `<new>`, the next
  milestone sets `<PackageValidationBaselineVersion>` in `Directory.Build.props` to
  `<new>` and replaces `build/baselines/` with the release's nupkgs (five since
  `CredProx.CallerTokens`; four before) **downloaded from the
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
  `dotnet pack /p:ApiCompatGenerateSuppressionFile=true`). The file was **deleted** at
  `0.8.1`, when every historical intentional removal (the 0.4.0 preset, the 0.5.0
  binary-level signature replacements, the 0.8.0 EntraObo removal) was already inside the
  baseline; **`0.11.0` ships it again** — `CredProx` and `CredProx.Abstractions` carry
  4 `CP0002` entries between them, exactly the member removals of the CHANGELOG
  `[0.11.0]` Breaking entry (the caller-contract constructor/deconstruct collapse), and
  the files are removed at the next baseline rotation, when those removals move into the
  baseline. A fresh-obj pack must show zero diagnostics **beyond the file's entries** and
  zero unnecessary-suppression warnings. Pre-1.0 the CHANGELOG
  preamble is the consumer contract.
- **Public-surface witness for a release that changes the API** (since `0.14.0`): beside
  APICompat, dump the public surface of the release tip and of the previously published
  bytes with two independent reflection dumpers, and diff on member identity (kind,
  assembly, owning type, member name), not line text. Each dumper has a blind spot the
  other covers: one emits no operator members, the other no base-type or interface
  lines. So the witness is the **union** of both diffs, and every line in it must map to
  a CHANGELOG entry. APICompat stays the packaged check (CP0008 covers base-list changes).
  The previously published bytes are the ones the registry serves: nothing is on nuget.org
  until that route is opened. Restore them outside the repo tree with a sha256 check
  against the release's recorded list. Inside the repo, the NuGet.Config maps `CredProx*`
  to the local folder feed of dev builds, so a restore there never reaches the registry.
- A credential failure in the library answers `502` (§3.4) — the status codes in
  `README`/plan are the contract; changing one is a plan change, not a packaging fix.

## Release history

- `0.13.1` (GitHub `61b6ef8eeabc5660582e7b74cf91539fefc00cbe`, release tip `a8a700f`, merged
  into `main` as `ecf965d`): **published 2026-11-20** — the M45 security patch. Security:
  credential acquisition and caller-token validation refuse HTTP redirects (affected:
  credential acquisition `0.3.0-preview.1`..`0.13.0`, caller-token validation
  `0.11.0`..`0.13.0`); JSON-escaped credential echoes are scrubbed (`0.7.0`..`0.13.0`); the
  scrubber's pass-through classes warn; provider-boundary messages carry the exception type
  only. Documentation: the production checklist, the credential-rotation runbook and the
  upgrade guide. No public API added, changed or removed. Prep (`a5e3f06`..`a8a700f`): the
  baseline rotation to the ten published `0.13.0` nupkgs, sha256-verified 10/10 (and
  re-derived by the checker from a fresh registry download); version `0.13.1` with the nine
  `CredProx*` pins; the CHANGELOG `[0.13.1]` entry; `main` merged in so the release tree
  carries the fixed soak harness (src unchanged: `git diff 691a484 a8a700f -- src` empty).
  Gates at `a8a700f`, run by the builder and re-derived independently by the checker:
  APICompat 10/10 (success phrase and package-validation target counted separately); a
  reflection diff of the public surface against the `0.13.0` dlls, additions 0 and
  removals 0 over all ten (814 entries, two independent dumpers); the build 0W/0E; the
  battery green, line coverage 0.9845 by the cobertura line-rate; all 18 sample smokes and
  `CredProx.SampleSmokes` 86/86 with every stamp `0.13.1+a8a700f…`; consumer compatibility
  against the published `0.13.0` bytes; disclosure scans zero hits. Release determinism holds
  at payload level (dll, pdb and nuspec byte-identical across packs); the nupkg container
  hash differs between packs only by NuGet's random core-properties name. Bench: the
  2026-11-19 differential at identical src (accepted delta `OAuthCacheHitScrub` +27..35 B/op,
  the cost of scrubbing escaped echoes; docs/benchmarks.md). Soak: the 4 h run at the
  security-fix src (2026-11-19 19:09-23:09Z) authenticated and proxied all 993,599 requests
  (k6 checks 993,599/993,599, proxy-log forwards equal to iterations, zero host refusals or
  caller-auth failures, zero secret-scan hits), and a 10-min run at `a8a700f` graded by that
  tree's own gate passed 41,399/41,399 with forwards equal to iterations. An earlier
  2026-11-19 soak was void (every request refused 401) and is not counted.
  Ceremony (2026-11-20): GitHub ONE squashed commit `61b6ef8` on the previous public tip
  `4ac539b`, noreply author and committer, tree identical to the release tip `a8a700f`; the
  annotated tag `c3c9b60` built with `git mktag` (noreply tagger, `+0000`, header
  `tag 0.13.1`), checked with `git cat-file -p` before the push (zero private-email hits).
  CI on the public commit, Actions run 44655029515: green on all three jobs, first attempt.
  Packed **once** from a clean detached worktree at the public commit,
  `-p:ContinuousIntegrationBuild=true`, fresh obj, isolated package cache: ten packages,
  every pack `cp=0 unnecessary=0`, and the APICompat success line on all ten. Sanity over all
  twenty packages (121 members): SourceLink carries the full public SHA and the `/_/` mapping
  in every symbol package, every nuspec names the public commit, every dll reads
  `0.13.1+61b6ef8…`, lib shape `net10.0`-only, zero private-path, private-mail, internal-host
  or key-material hits. The registry served nothing at `0.13.1` before the push. Push round:
  ten nupkgs, each exactly once; all twenty PUTs answered `201 Created`. Nupkg sha256:
  `CredProx` `740dc87f35af29cc59c3349deb2f350df76bd218c4ad5a723f661650223e30c6`,
  `CredProx.Abstractions` `569d42bd100946993272b34e17ed04f248af1788a1acba720577ffa7c9c2caa3`,
  `CredProx.AzureKeyVault` `b45fe46c942db33e6ef9e98572f28866fae7451dd30a68100d659ecfb267a9e8`,
  `CredProx.CallerKeys` `ed85f747f9550cfcda2c8e6d9d079b60eeee2842556681815d06d2c9ae8cb001`,
  `CredProx.CallerTokens` `5ec9a232d6273aa456e9d03e0c42594a9d741d6d4fcfe84e825babe226ea1551`,
  `CredProx.Hmac` `5ea460ef2cb1efeffeca58ece6c7707f1ccaabadfe7a079f4bc5b683b8856d2d`,
  `CredProx.LoginExchange` `17143d012c4e62ab5c1db42d56aa213c69ca3221bcc5793028ce76c5f83acc8f`,
  `CredProx.OAuth` `9235ca2197b5e174ec6e40b821de0d3d60145b7e86d90246abf07a5072cbefd1`,
  `CredProx.Operations` `95fdbdef11a5b679705a5c624e8e8a9522ceae08db8b891241f394886dfefa9e`,
  `CredProx.Testing` `fe1f33a6221cb0f269be6ca92c2c9cac0a3ba72f8197f6315c30c3bc2bf1eb9e`.
  Consumer verification: an isolated package cache with a cleared http-cache restored all
  ten from the registry, byte-identical 10/10 to the pushed files; the QuickStart smoke
  passed on those downloaded bytes (3/3, loaded `CredProx` `0.13.1+61b6ef8…`). **Not
  verified at publish:** the SourceLink debugger step-through (CI asserts the path form) and
  the consumer-side `.snupkg` download path. **Known gap:** the nightly fuzz job's `parsers`
  target recorded zero executions on 2026-11-19 (the harness instrumented `CredProx.dll` but
  not `CredProx.Hmac.dll`, which the target reaches first since the `0.12.0` package split,
  so the fuzzer aborted before its first case; no crash found). The gate that fails on zero
  executions arrived in `0.13.0`, so before it the same no-op run passed silently: the
  parsers target has likely not fuzzed anything since `0.12.0`. The other five targets,
  including the scrubber, ran green. Restoring executions alone would not have made the
  target able to report on its two header invariants either: the BCL header validator
  refused every value carrying the separator, so the canonical-string comparison could
  never be handed two genuinely distinct requests, and the media-type leg only ever saw
  bytes the media-type parser refused — both were made reachable on 2026-11-20 (values
  fed via `TryAddWithoutValidation`; media split into its own target with its own
  corpus).
- `0.13.0` (GitHub `4ac539bd5d00ae42fa11032a4f0d09294381b19e`, internal release commit
  `9b23040`, the merge of `release-0.13.0` at `302219d`): **published 2026-11-19** — M43.
  Fixed: caller-key rotation under upper-cased configuration sources (the published `0.12.0`
  carries the defective rebind gate); the per-request attach-arm delegate. Changed:
  `CredProx:Health:Enabled=false` registers neither the probe loop nor the `credprox` check
  (ADR-0006). Additive only. Prep (`a6557e2`..`302219d`): the baseline rotation to the ten
  published `0.12.0` nupkgs, sha256-verified 10/10 against the `0.12.0` entry, with package
  validation turned on for the six packages that first shipped in `0.12.0` and the `0.11.0`
  suppression files removed; version `0.13.0` with the nine `CredProx*` pins; the CHANGELOG
  `[0.13.0]` entry. Gates at the prep candidate `dc097b3`, run by the builder and re-derived
  independently by the checker with planted-break controls: APICompat 10/10, the build
  0W/0E, the battery and coverage green, doc guards 29/29, all 18 sample smokes and
  `CredProx.SampleSmokes` 86/86 with every stamp `0.13.0+dc097b3…`, consumer matrix 15/15
  against the prep commit, disclosure scans zero hits. Bench vs `baselines/0.12.0`:
  `13 methods compared, FAIL=0 WARN=2`, both timing-only warn-mode on a shared machine
  (`OAuthCacheHitScrub` ratio 1.41; the plain-YARP control moved ×1.44 in the same run);
  the attach arms recovered 108–110 B per request. The two commits after `dc097b3` are
  text-only (`b41f510`, `302219d`).
  Ceremony (2026-11-19): GitHub ONE squashed commit `4ac539b` on the previous public tip
  `5cc1a7e`, noreply author and committer, tree identical to `9b23040`; the annotated tag
  built with `git mktag` from explicit text (noreply tagger, `+0000`, header `tag 0.13.0`)
  and checked with `git cat-file -p` before the push (zero private-email hits); a regular
  append. CI on the public commit, Actions run 44453961849: green on all three jobs, first
  attempt. Packed **once** from a clean detached worktree at the public commit,
  `-p:ContinuousIntegrationBuild=true`, fresh obj, isolated package cache: ten packages,
  every pack `cp=0 unnecessary=0`, and the APICompat success line on all ten. Sanity over
  all twenty packages (121 members): SourceLink carries the full public SHA and the `/_/`
  mapping in every symbol package, every nuspec names the public commit, every dll reads
  `0.13.0+4ac539b…`, lib shape `net10.0`-only, zero private-path, private-mail,
  internal-host or key-material hits. The registry served nothing at `0.13.0` before the
  push. Push round: ten nupkgs, each exactly once (the client auto-routed the snupkgs);
  all twenty PUTs answered `201 Created`. Nupkg sha256:
  `CredProx` `2757236c83ccdae7806b17582c915ed796bc1001fa974af39cea3933df1ffaa7`,
  `CredProx.Abstractions` `3886cd5af1354534fdb745c28e4ed8ade5e843fcc9645f7085c48ee9b98c285f`,
  `CredProx.AzureKeyVault` `b261e72341ca9f0909221131ee802d7cecee6e0b27e23ffdd3ada0d59efca6f8`,
  `CredProx.CallerKeys` `3008e32c648f161b53c1274c344821c3885d10e7a169e744130ca24a932284de`,
  `CredProx.CallerTokens` `c09d2d4b3e494b464670b88cdecbfb64b6641d409002d78ad11edb338144b5e4`,
  `CredProx.Hmac` `de50dc14f99d617425c317791cdbfb877427591b210b00fb9c62fcf72478cccf`,
  `CredProx.LoginExchange` `8c93886972074198934fc659f199685661a022114f3c15bc9b60f220bbe12081`,
  `CredProx.OAuth` `8dcbc8ed487d1a693f03813e78898c4a2352e97aa251dc9613da29e4880f126b`,
  `CredProx.Operations` `57242801a9eb10a39b6728fa42ab8c4e8f3efc078168b89d8815c7f3ee9be3ff`,
  `CredProx.Testing` `95edf261c1fbf316c430d1cd93832a6b55f799d330ea722849e0ff61473b4b65`.
  Consumer verification: an isolated package cache with a cleared http-cache restored all
  ten from the registry, byte-identical 10/10 to the pushed files; the QuickStart smoke
  passed on those downloaded bytes (3/3, loaded `CredProx` `0.13.0+4ac539b…`). **Not
  verified at publish:** the SourceLink debugger step-through (CI asserts the path form),
  the consumer-side `.snupkg` download path, and the post-publish benchmark refresh to
  `baselines/0.13.0` (runs next). The refresh ran (2026-11-19): a full pass at main
  `f46ca3d` — src identical to the release tree (`git diff --stat 9b23040 f46ca3d -- src`
  empty; `9b23040`'s src equals the release candidate `302219d`) — on a quiet machine (the
  1-minute load was waited below 1.5 before launch), gated against `baselines/0.12.0`:
  `bench-compare: 13 methods compared, FAIL=0 WARN=2` (compare exit 0) — both WARNs are
  warn-mode timing-only arms whose allocations came in lower than 0.12.0, inside the
  documented noise bands (docs/benchmarks.md); the three credential-attach arms recovered
  their pre-0.12.0 allocations (7,977→7,864, 9,840→9,731, 7,574→7,457 B), every other arm
  flat or better, `N=13–15`; `baselines/0.13.0/MACHINE.md` records the environment and the
  measured line, and the baseline folder now holds the `0.13.0` bytes. Gate: full-solution
  Release build 0 Warning(s) / 0 Error(s); doc guards 29/29 (measured at `f46ca3d`, whose
  src equals the measured release bytes).

- `0.12.0` (GitHub `5cc1a7edbdd50c1ad66a89c002ea8a69f4eac90c`, internal release commit
  `682a676`): **prepared 2026-11-17, published 2026-11-18** — the M42 package split
  (ADR-0005): ten packages at one version. The core keeps the pipeline, the configuration
  secret stack, `StaticKey`, caller policy, header hygiene, audit and problem responses;
  OAuth, LoginExchange, Hmac, the Operations features, caller keys and agent tokens ship
  as six feature packages, joining `CredProx`, `CredProx.Abstractions`,
  `CredProx.AzureKeyVault` and `CredProx.Testing` (four to ten). Breaking: the split is
  binary-breaking for hosts referencing moved types (recompile against both packages);
  the CHANGELOG `[0.12.0]` Breaking entries name every moved and removed type — the
  45+2 APICompat suppressions map to those entries one-for-one against the rotated
  `0.11.0` baseline. Baseline rotation ran in prep: the four published `0.11.0` nupkgs,
  sha256-verified (ADR-0001). Gates at the prep commit `e10f18c0a622d75c3af6313d2d75cc9234c2f25c`:
  pack ×10 from fresh obj answered `cp=0 unnecessary=0` on every package, APICompat active
  only on the four baselined packages; ten nupkgs, no `-dev` name; the exact-version cache
  evicted (leftover 0) and rebuilt — every loaded and packed assembly reads
  `0.12.0+e10f18c0a…`, zero `-dev` bytes in bins or packages. Battery: 1902 unit + 35 security
  + 40 conformance tests, 0 failed / 0 skipped, coverage gate green on all ten; E2E 3/3;
  Load 7/7; the build Release-clean (0W/0E). Sample smokes: all 18 wrappers green, port
  uniqueness green, `CredProx.SampleSmokes` 85/85 with the loaded-library stamp gate on.
  Consumer matrix: 15/15 PASS against the local `0.12.0` feed at the prep commit. ACA
  harness: image built, offline proxy smoke `SMOKE OK`. Bench vs `baselines/0.11.0`:
  13 methods compared, `FAIL=3` — the three credential-attach arms measure +108…118 B
  per request at the gate, and +105…128 B across six passes on identical code
  (`StaticKeyAttach` varies by up to 17 B between runs); **accepted
  by the maintainer**
  as the measured cost of the release delta (docs/benchmarks.md, "Accepted release-delta
  allocations"), the other ten arms unchanged or better; the baseline rotates at the
  post-publish refresh. Disclosure scans over the tracked tree, the release diff and the
  commit messages: zero hits (the private-key-marker matches in the tree are the
  detector's own code).
  Ceremony (2026-11-18): a text-only fold after the check (`682a676`, the measured
  attach-arm spread replacing a noise-band claim) is the internal release commit. GitHub:
  ONE squashed commit `5cc1a7e` on the previous public tip `f239384`, noreply author and
  committer, tree identical to `682a676`; the annotated tag built with `git mktag` from
  explicit text (noreply tagger, `+0000`, header `tag 0.12.0`) and checked with
  `git cat-file -p` before the push (zero private-email hits); a regular append, no tag
  deletions. CI on the public commit, Actions run 44213003116: attempt 1 failed one sample
  cell (`AgentEgressSmokeTests.Audit_RecordsCallsPerAgent_NoCredentialValueAnywhere`), a
  test-side race in which the cell waits for the first audit line naming the caller and can
  assert before the proxied call's line is written; attempt 2 green on all three jobs. The
  packages carry no test code; the race fix follows on `main`. Packed **once** from a clean
  detached worktree at the public commit, `-p:ContinuousIntegrationBuild=true`, fresh obj,
  isolated package cache: ten packages, zero CP diagnostics, APICompat run on the four
  baselined packages. Sanity loop ×10: SourceLink carries the full public SHA and the `/_/`
  mapping in every symbol package, no builder-home paths in any pdb or dll, lib shape
  `net10.0`-only, every dll `0.12.0+5cc1a7e…`, every nuspec naming the public commit;
  member-wise disclosure scan over all twenty packages (71 members) zero hits. The registry
  served nothing at `0.12.0` before the push. Push round: ten nupkgs (the client
  auto-routes the adjacent snupkgs), each exactly once; every PUT answered `201 Created`.
  Nupkg sha256: `CredProx` `cb274794c0091aa26a304ac67c1bbf6f89cb19089e7be0fc9e6b90014312b72a`,
  `CredProx.Abstractions` `edc724067e25f639e2a632285ca85f5dbd52699aa0ef4ea8ced8fefc0d7928fe`,
  `CredProx.AzureKeyVault` `482a8ccf16533757d05021236e211bb9957c916aded83f157b1b89fd5fb21e92`,
  `CredProx.CallerKeys` `6cc70ea28f752818424347c2687df301244eab2a1335024434484ce8aa08b193`,
  `CredProx.CallerTokens` `6055e4df26af6b8c71b6190ee47a2044abd33b77be981db83dcd272c9073df53`,
  `CredProx.Hmac` `751803b79eeb2999477ff73a69e01ff0f008f7be0a9cbc4052fc612eec0d5754`,
  `CredProx.LoginExchange` `a9084150ca7ae1facdd1c8282249327514331516af27a337cf6cde7df399dd17`,
  `CredProx.OAuth` `6f15280b82b38814741cbc706b5c5a480fc6567729988b83408e40ea1cb42994`,
  `CredProx.Operations` `59db2380dfa8f6f9ac8553036f0ee55aa40cb67762792848e2c79031c5a96e35`,
  `CredProx.Testing` `7b987ece983ba1245efb77a1436559eb9df705541298e10685eed404f35499d5`.
  Consumer verify: http-cache cleared, out-of-repo scratch project, isolated package cache,
  all ten downloads byte-identical to the pushed artifacts; `samples/QuickStart` smoke green
  (3/3, loaded-library stamp gate on) with its loaded `CredProx.dll` byte-identical to the
  downloaded one. **Not verified at publish:** the SourceLink debugger step-through (CI
  asserts the path form instead), the consumer-side `.snupkg` download path, and the
  post-publish benchmark refresh (runs next, on a quiet machine). The refresh ran
  (2026-11-18): a full pass at main `0feb05a` — src identical to the release tree
  (`git diff --stat 682a676 0feb05a -- src` empty) — on a quiet machine, gated against
  `baselines/0.11.0`: `bench-compare: 13 methods compared, FAIL=3 WARN=0` (compare exit 1)
  — the three FAILs are exactly the accepted credential-attach arms at their recorded cost
  (+113/+105/+117 B, each inside its arm's spread of +112…113, +105…108 and +111…128 B
  across six identical-code passes; docs/benchmarks.md,
  "Accepted release-delta allocations"), the other ten arms unchanged or inside their
  documented allowances — `SseCredProx`, `SsePlain` and `TokenCacheBenchmarks.SingleFlight`
  rose, each inside its allowance — and statistics depth `N=13` on `OAuthCacheHit`, `N=14`
  on `OAuthCacheHitScrub`, `N=15` on the other eleven, all above the floor of 10;
  `baselines/0.12.0/MACHINE.md` records the environment and the measured line, and the
  baseline folder now holds the `0.12.0` bytes. Gate: full-solution Release build
  0 Warning(s) / 0 Error(s); doc-snippet tests 21/21 (both classes, measured at the
  pre-commit tree equal to this content).

- `0.11.0` (GitHub `f23938405d797f4dfc6564faaa7bdfb5dff2599a`, internal release commit
  `1fa3b6b`): published 2026-11-16 — agent tokens (M39, ADR-0004; sample E19): an agent
  presents a short-lived Microsoft Entra (or any OIDC) access token instead of a stored
  secret, and Entra app roles narrow it to named rules — a token gets exactly the
  operations its roles name, and a caller without named rules admits no token; caller API
  keys keep working unchanged. The caller-token API is additive; docs lead with the most
  useful examples and the Spotify example is removed (M40). One Breaking change: the
  caller contract surface (`CallerDefinition`, `CallerOperationRule`, `CallerIdentity`)
  collapses to single constructors with optional parameters — migration is a recompile,
  positional call sites need no edits, and deconstructing a `CallerIdentity` now takes
  three variables. The test battery was measured at the prep commit `8ae20d8` — the delta
  to the release commit `1fa3b6b` is CHANGELOG text only — and passed there in full:
  packs ×4 with APICompat run proven, full-solution build 0 Warning(s) / 0 Error(s),
  1769 + 35 Security + 40 Conformance tests, coverage at or above every project's floor
  (98.0/93.9, 100.0, 99.0, 94.6), 3 E2E + 7 Load, 18 samples build, 7/7 sample smokes
  including E19, disclosure scans (four secret shapes and internal-URL shapes over the
  tracked tree, the release diff and the commit messages) zero hits. The release bench
  gate ran on the prep-check pass and printed `bench-compare: 13 methods compared,
  FAIL=0 WARN=4` (compare exit 0; the WARNs are the documented warn-mode overhead/SSE
  arms — `FAIL=0` is the stable signal on this machine). Ceremony: packed **once** from a
  clean detached worktree at the PUBLIC commit after tree equality with `1fa3b6b`,
  `-p:ContinuousIntegrationBuild=true` from fresh obj into an isolated package cache;
  sanity loop ×4 passed (SourceLink carries the full public SHA and the `/_/*`-to-raw
  mapping in every symbol package; no builder-home paths in any pdb or dll; in-package lib
  shape `net10.0`-only, matching the published baselines); member-wise disclosure scan
  over all eight packages (49 members) zero hits. The push round: four nupkgs (the client
  auto-routes the adjacent snupkgs), each version exactly once — every PUT answered
  `201 Created`; the push logs record URL and credentials redacted. Nupkg sha256:
  `CredProx` `6934294cecab55ef0326bb8c46decd05f8355f76549537743fa9a91abb7afc45`,
  `CredProx.Abstractions` `8da80fffd950ab737f4a74f5423e75ef34aa344c830cdabf020af04abea987ca`,
  `CredProx.AzureKeyVault` `25d78cc78cc3bef957d975eb6c4ece3c7fff4677a66bfd1024fbe4a22f1312c2`,
  `CredProx.Testing` `0ab2ccae9a33a7879e67419c9aad8c5a78ea3e61a47c3e7ad20dce07c2b9a7a5`.
  APICompat honesty: APICompat was not re-run by log line at the public SHA `f239384` —
  the pack-once run proved it via 4/4 fresh per-project validation semaphores (the gate's
  messages are Low-importance and absent from minimal-verbosity logs by design), and that
  is sufficient because the tree is unchanged along `8ae20d8` → `1fa3b6b` → `f239384` (a
  CHANGELOG-only delta); an independent verification against the published `0.10.0`
  baselines showed log-line APICompat passes on all four packages plus a
  suppression-sabotage probe covering the same surface. Consumer verify: http-cache
  cleared, out-of-repo scratch project, isolated package cache, all four downloads
  byte-identical to the pushed artifacts (served `contentHash` byte-for-byte), each served
  nuspec carrying commit `f239384`, the loaded dll reporting `0.11.0+f23938405d…`
  InformationalVersion; `samples/QuickStart` smoke green on those exact bytes. GitHub:
  ONE squashed commit on the previous public tip `3ba5264`, noreply identity — a regular
  append, no collapse, no tag deletions; the fresh-clone audit confirmed one new commit,
  tree equality with `1fa3b6b` and zero disclosure hits; CI green (Actions run
  43796995079, all three jobs). **Tag incident:** the first public tag object carried a
  private tagger email and the creation refname in its header. It was replaced within
  minutes in precedent form — `git mktag` from explicit text, noreply tagger, `+0000`,
  header `tag 0.11.0` — and the discarded object is **not in the published history**: no
  branch or tag references it. It does remain fetchable by exact SHA until GitHub collects
  unreachable objects or a Support purge is requested, so it is not correct to say it was
  never exposed. The ceremony lesson is recorded in the Rules section above.
  **Not verified at publish (kept honest):** the SourceLink debugger step-through (CI
  asserts the path form in the packed PDBs instead); the consumer-side `.snupkg` download
  path (symbol packages were checked at pack time only); the consumer smoke ran the
  in-process `--smoke` stand-in, not the Docker/WireMock E1 variant. Benchmarks: the
  post-publish refresh pass on a quiet machine, gated against `baselines/0.10.0`:
  `bench-compare: 13 methods compared, FAIL=0 WARN=5` (all five WARNs are warn-mode
  overhead-suite arms — `OAuthCacheHit` ratio ×1.35, `OAuthCacheHitScrub` ratio ×2.38 and
  mean ×1.87, `SseCredProx` ratio ×1.55 with allocations down to 11,751 B, `SsePlain`
  ratio ×1.30 with allocations down to 9,035 B, `StaticKeyAttach` ratio ×1.67 and mean
  ×1.32 — inside the documented echo-arm noise band; the allocation gate is green,
  `SingleFlight` 23,457 B inside its `max(32 B, 1 %)` allowance) — this pass became
  `baselines/0.11.0/` (`MACHINE.md` records the environment).

- `0.10.0` (GitHub `3ba52649c85a3d8b56ab4473c7ea87678e7ac3ba`, internal release commit
  `6f247e0`): published 2026-11-15 — the M38 token-lifetime policy (minor): vendor-stated expiry
  (`expires_in`, `expires_at`) now follows one invariant grammar on all three credential
  providers. An explicit offset or `Z` is read exactly as before; an accepted vendor lifetime
  above 24 h is capped to 24 h (`DefaultLifetime` is never capped); non-numeric, non-finite and
  thousands-grouped values reject through the protocol-violation path with nothing cached;
  `JwtAssertion`'s `expires_at` accepts epoch seconds and an invariant ISO-8601 grammar
  (offset-less means UTC); an already-past expiry rejects as unusable. The token cache floors
  its refresh arithmetic at `DateTimeOffset.MinValue`. Public surface: additive optional-`ILogger`
  constructor overloads on `TokenExchangeProvider` and `JwtAssertionProvider` only; no existing
  API changed. The benchmark gate's SSE allocation arms became warn-above-12 % /
  hard-FAIL-above-2.5× after the 2026-11-15 interleaved A/B attribution: at unchanged workload
  the RELEASED-code control itself reached 16,578 B (1.26× — its own maximum across six
  quiet-gated passes) while the candidate tail reached 25,567 B (1.95×) with none of the changed
  code in the arm's path, so a fixed 12 % FAIL could not identify a code change. The test battery
  was measured at the prep commit `f84a116` — the delta to the release commit `6f247e0` is
  docs-only ×2 plus comment-only src/tests (18 lines, zero non-comment), and a fresh-context
  prep check passed `f84a116`. The release gate itself ran on the preserved prep-check bench
  bytes (sha256 20/20) with the shipped `f84a116` gate script and printed
  `bench-compare: 13 methods compared, FAIL=0 WARN=4` (`OAuthCacheHit`, `OAuthCacheHitScrub`,
  `StaticKeyAttach`, `SseCredProx` 23,149 B = 1.76×); the released `8df333c` script on the same
  bytes prints `FAIL=1 WARN=3` — its FAIL is that same `SseCredProx` allocation arm the gate
  change above addresses. Benchmarks: the post-publish refresh pass at `6f247e0` on a quiet
  machine gated against the `0.9.4` baseline:
  `bench-compare: 13 methods compared, FAIL=0 WARN=3` (all three WARNs are warn-mode
  overhead-suite checks: `OAuthCacheHit` ratio ×1.19, `SseCredProx` ratio ×1.44, and
  `SsePlain` allocations 8,325→9,960 B above its 12 % warn allowance and far below the
  2.5× hard-FAIL — the M37-recorded non-deterministic arm; `SseCredProx` 13,618 B inside
  its allowance, `SingleFlight` 23,434 B inside its 23,444–23,520 B band). A second quiet
  pass on the same commit ~25 min earlier printed `FAIL=0 WARN=5` with the same arms plus
  two warn-mode ratio drifts inside the documented ×1.6–2.8 echo noise — the WARN count
  moves pass to pass on this shared machine and `FAIL=0` is the stable signal; the pass
  above is the one that became `baselines/0.10.0/` (`MACHINE.md` records the environment).
  Ceremony: packed **once** from a clean detached worktree at the PUBLIC commit after tree
  equality with `6f247e0`, `-p:ContinuousIntegrationBuild=true` from fresh obj into an isolated
  package cache; sanity loop ×4 passed (SourceLink carries the full public SHA and the
  `/_/*`-to-raw mapping in every symbol package; no builder-home paths in any pdb or dll);
  APICompat against the rotated `0.9.4` baselines exit 0 on all four packages (validation run
  proven by the per-project `Microsoft.NET.ApiCompat.ValidatePackage.semaphore` — its messages
  are Low-importance and absent from minimal-verbosity logs by design); member-wise disclosure
  scan over all eight packages zero hits. The push round: four nupkgs (the client auto-routes
  the adjacent snupkgs), each version exactly once — every PUT answered `201 Created`; pushes
  authenticate via the machine-local `packageSourceCredentials`, serving proven consumer-side.
  Nupkg sha256: `CredProx` `38235f8d20776ff06cfd785853a29f554e43f904e81d1bb83a4ba99d0c50bc1a`,
  `CredProx.Abstractions` `ae5b3494c3428c4c0b8f25d8daf645fa3c7fc8e94a5634131d237e504f8a31aa`,
  `CredProx.AzureKeyVault` `44975f741ade7736d13165a7b3a9b799f09f9eda8a00de8a960dd8b7591a0643`,
  `CredProx.Testing` `b8ed195d6b9ed96f5ebc44294f85953cb517f5b04dff03af459373d0ad3a5e42`.
  Consumer verify: http-cache cleared, out-of-repo scratch project, isolated package cache, all
  four downloads byte-identical to the pushed artifacts, each served nuspec carrying commit
  `3ba5264`; `samples/QuickStart` smoke green on those exact bytes. **Not verified at publish
  (kept honest):** the SourceLink debugger step-through (CI asserts the path form in the packed
  PDBs instead); the consumer-side `.snupkg` download path (symbol packages were checked at pack
  time only); the QuickStart smoke ran the in-process `--smoke` stand-in, not the Docker/WireMock
  E1 variant. GitHub: ONE squashed commit on the previous public tip `ca814c7`, noreply identity
  — a regular append, no collapse, no tag deletions; the fresh-clone audit confirmed one new
  commit, tree equality with `6f247e0` and zero disclosure hits; CI green (Actions run 43765381059,
  all three jobs).

- `0.9.4` (GitHub `ca814c7bf0a5ccce0997a2c2f2a185ed669049d7`, internal release commit
  `8df333c`): published 2026-11-15 — library hardening patch (M37): the vendor
  `expires_in` is now parsed with the canonical JSON-number grammar on all three
  credential providers. Negative values reject through the protocol-violation path on
  all three; non-finite and thousands-grouped values reject on the OAuth
  client-credentials provider while the other two providers keep the `DefaultLifetime`
  fallback, pending the lifetime-policy decision. **Nothing is cached on any
  rejection.** No public API change. The benchmark regression gate gained a
  statistics-count floor, per-arm N/P95 printing, parameter-aware comparison keys and
  loud partial-run rules, and the SSE benchmark workload now measures real per-event
  redaction over a bounded stream. The test battery was measured at the prep commit
  `0c0fbc1` — the delta from it to the release commit `8df333c` is CHANGELOG text only
  (the per-provider preamble correction); a fresh-context prep check passed `0c0fbc1`
  (baseline sha256s against the published record, APICompat proven to have run, the
  four sample smokes on documented ports including E6 and E18). Benchmarks:
  the full `--filter '*'` release-record pass on a quiet machine ran at `0c0fbc1` —
  gate vs the `0.9.3` baseline: `bench-compare: 13 methods compared, FAIL=0 WARN=2`
  (the two WARNs are warn-mode absolute-mean drifts in the overhead suite,
  OAuthCacheHitScrub x1.57 and PlainYarp x1.38 with the plain control arm itself
  +38 % — machine-wide residual; same-run ratios normal or improved; the allocation
  gate is green: `SseCredProx` 14,622 B inside its 12 % allowance, `SingleFlight`
  23,456 B inside the max(32 B, 1 %) allowance). The post-publish refresh pass at the
  release commit `8df333c` on a quiet machine printed the identical summary against
  the same reference (`SseCredProx` 13,117 B, `SingleFlight` 23,449 B — inside the
  measured scheduling band) and became `baselines/0.9.4/` (`MACHINE.md` records the
  pass). Ceremony: packed **once** from a clean detached worktree at the PUBLIC commit
  after tree equality with the reviewed `8df333c`, `-p:ContinuousIntegrationBuild=true`
  from fresh obj into an isolated package cache; sanity loop ×4 passed (SourceLink
  carries the full public SHA and the `/_/*`-to-raw mapping in every symbol package;
  no builder-home paths in any pdb or dll); APICompat against the rotated `0.9.3`
  baselines exit 0 on all four packages, no surface change; extended disclosure scan
  over every member of all eight packages (49 members incl all eight
  `*Content_Types*` members) zero hits, exit code captured without a pipe tail. The
  push round: four nupkgs (the client auto-routes the adjacent snupkgs), each version
  exactly once — every PUT answered `201 Created`; pushes authenticate via the
  machine-local `packageSourceCredentials`, serving proven consumer-side. Nupkg
  sha256: `CredProx`
  `22783b2569a2a7b24b368f797f7c385bba537612dec7f144f9600babcd5b33d8`,
  `CredProx.Abstractions`
  `1bca146ccf0c9f8584f187059fedceab680309e9adc26cac8f9ee6cb8cbc2892`,
  `CredProx.AzureKeyVault`
  `00333b451cc846591e1934b0054fea7f8392633c9293b924b2a2afe2c72f6b00`,
  `CredProx.Testing`
  `a3e93911a35169610dcac7c894d25068f1f183c992d37ab138426e51e8a48998`. Consumer verify:
  http-cache cleared, out-of-repo scratch project (the repo-level source mapping pins
  `CredProx*` to the local feed, so an in-tree restore cannot prove the registry),
  isolated package cache, all four downloads byte-identical to the pushed artifacts,
  an independent re-check confirming the four hashes and the `ca814c7` commit in every
  served nuspec, `samples/QuickStart` smoke green on those exact bytes (WireMock
  journal shows the credential attached; the caller's echo shows it redacted). GitHub:
  ONE squashed commit on the previous public tip `02e495cc`, noreply identity — a
  regular append, no collapse, no tag deletions; the fresh-clone audit confirmed one
  new commit, tree equality with `8df333c` and zero disclosure hits; CI green (Actions
  run 43680224691, all three jobs, the Examples job including the E6 ADP and E18
  CallerApiKey smoke steps). The benchmark baseline was refreshed from the pass at the
  release commit (`baselines/0.9.4/`).
- `0.9.3` (GitHub `02e495cc2d082903804b82a6da85565625ff8a25`, internal release commit
  `d3896d0`): published 2026-11-11 — patch release, samples, documentation, CI and
  benchmark-tooling only: **no library or public API change** (`src/` byte-identical to
  `0.9.2`). Content: the E6 ADP example rebuilt to the known-working certificate
  arrangement (OAuth client credentials plus one named mTLS client certificate
  presented on both the token call and the API calls, base64 passwordless PKCS#12,
  with a Key Vault variant whose live rotation reaching new connections the offline
  stack witnesses); the new E18 caller API-key example (keys as pure configuration,
  missing and wrong keys indistinguishable, the key stripped before forwarding);
  fixed real-vendor secret-delivery instructions in the ADP, Spotify, MicrosoftGraph
  and QuickStart examples (the previously published hyphenated environment-variable
  form is refused by bash; the published secret names keep their hyphens, delivery
  now uses one bash-valid form); CI extended to smoke E6 and E18. The benchmark
  regression gate gained a per-arm allocation allowance for the timing-sensitive
  single-flight arm — owner ruling: fix the gate, no release exemption.
  `TokenCacheBenchmarks.SingleFlight` runs 64 concurrent waiters on a cold key, and
  its per-op allocation follows scheduling: measured band 23,444–23,520 B at
  unchanged `src/`. The allowance keys on the exact `(suite, method)` pair, is
  max(32 B, 1 % of the baseline), leaves every other arm on the flat 32 B default,
  keeps the SSE arms at 8 %, and prints the applied allowance on every gated arm
  (`docs/benchmarks.md`). Benchmarks: the full `--filter '*'` release-record pass on
  a quiet machine ran at commit `603dc5b` — the deltas from it to the release commit
  `d3896d0` are text and gate-script only (`CHANGELOG.md`, `docs/benchmarks.md`,
  `docs/credprox-plan.md`, `scripts/bench-compare.sh`); `src/` and the benchmark
  code are byte-identical — gate summary:
  `bench-compare: 13 methods compared, FAIL=0 WARN=3` (the three WARNs are the known
  overhead-suite warn-mode mean drifts; the allocation gate is green and
  `SingleFlight` measured 23,383 B, below the committed baseline unaided). The
  post-publish refresh pass at the release commit `d3896d0` printed the identical
  summary against the `0.9.2` reference (`SingleFlight` 23,520 B, inside the
  measured band) and became `baselines/0.9.3/` (`MACHINE.md` records the pass). The
  test battery was measured at the prep commit `57bef10` — the deltas from it to
  `d3896d0` are text-only and gate-script-only. A fresh-context prep check passed
  `57bef10` (baseline sha256s against the published record, APICompat proven to have
  run); the gate change passed its own check at `54cfef7` (identical-bytes re-gate,
  sabotage probes both directions, untouched-coverage proof); the override-fold fix
  passed at `d3896d0`; the samples rode the M36 security pass and two rechecks.
  Ceremony: packed **once** from a clean detached worktree at the PUBLIC commit after
  tree equality with the reviewed `d3896d0`, `-p:ContinuousIntegrationBuild=true`
  from fresh obj into an isolated package cache; sanity loop ×4 passed (SourceLink
  carries the full public SHA and the `/_/*`-to-raw mapping in every symbol package;
  no builder-home paths in any pdb or dll); APICompat against the rotated `0.9.2`
  baselines exit 0, no surface change; extended disclosure scan over every member of
  all eight packages (49 members incl all eight `*Content_Types*` members) zero hits,
  exit code captured without a pipe tail. The push round: four nupkgs (the client
  auto-routes the adjacent snupkgs), each version exactly once — pushes authenticate
  via the machine-local `packageSourceCredentials`, serving proven consumer-side.
  Nupkg sha256: `CredProx`
  `c4624cb4e762905d639f80832be44ffd96acbdd034da1ebbea01653a39271f3e`,
  `CredProx.Abstractions`
  `0bd160689017c7991135d9d3f15b7d509e6f8fa188b37bf871c1d770b1b2e7c1`,
  `CredProx.AzureKeyVault`
  `360d5dd9c5c7ee886ad5d158bb081eb8c11b2eb4e7f2d1a70a6ba46e4f0f2e9e`,
  `CredProx.Testing`
  `02709b32ac71ecf3c0b924b88dac8b8439e0f2aab2f2677ed0bf0799f2c6adce`. Consumer verify:
  http-cache cleared, out-of-repo scratch project (the repo-level source mapping pins
  `CredProx*` to the local feed, so an in-tree restore cannot prove the registry),
  isolated package cache, all four downloads byte-identical to the pushed artifacts,
  an independent re-check confirming the four hashes and the `02e495cc` commit in
  every nuspec, `samples/QuickStart` smoke green on those exact bytes (WireMock
  journal shows the credential attached; the caller's echo shows it redacted).
  GitHub: ONE squashed commit on the previous public tip, noreply identity — a
  regular append, no collapse, no tag deletions; CI green (Actions run 43039565880,
  all three jobs, the Examples job now including the E6 ADP and E18 CallerApiKey
  smoke steps). The benchmark baseline was refreshed from the pass at the release
  commit (`baselines/0.9.3/`).
- `0.9.2` (GitHub `ed6a527ff308458b209a96cb85e71c994aa252e0`, internal release commit
  `7dc8c70`): published 2026-11-10 — patch release, the first gated by the M34
  benchmark gate: a full `--filter '*'` pass on a quiet machine at the prep commit
  `715f425` (text-only delta to the release commit), compared against the committed `0.9.1` reference — gate summary:
  `bench-compare: 13 methods compared, FAIL=0 WARN=1` (the single WARN is the known
  OAuthCacheHitScrub warn-mode timing drift; the allocation gate, which is what the
  suite declares, is green). Content: hot-path allocation cut about 77 % per scrubbed
  proxied request and 24–30 % per scrubbed SSE connection (SSE across three
  independent runs 81,129–88,747 B); the scrubbing pool never returns a buffer while a
  read is in flight (dispose transfers ownership; late-landing bytes are discarded and
  the reader gets `ObjectDisposedException`; post-dispose reads refuse on every path),
  plus a separate fix for the pre-existing post-dispose upstream reads; the benchmark
  regression suite and its comparison gate join the repository. No public API change.
  The prep commit `715f425` (baseline rotation to the published `0.9.1` bytes —
  sha256-verified, ADR-0001 — version bump, CHANGELOG) passed a fresh-context prep
  check; five text-only findings were folded into `7dc8c70` before publish. Ceremony:
  packed **once** from a clean detached worktree at the PUBLIC commit after tree
  equality with the reviewed `7dc8c70`, `-p:ContinuousIntegrationBuild=true` from
  fresh obj into an isolated package cache; sanity loop ×4 passed (SourceLink carries
  the full public SHA and the `/_/*`-to-raw mapping in every symbol package; no
  builder-home paths in any pdb or dll); APICompat against the rotated `0.9.1`
  baselines exit 0, additive surface only; extended disclosure scan over every member
  of all eight packages (49 members incl all eight `*Content_Types*` members) zero
  hits, exit code captured without a pipe tail. The push round: four nupkgs (the
  client auto-routes the adjacent snupkgs), each version exactly once — pushes
  authenticate via the machine-local `packageSourceCredentials`, serving proven
  consumer-side. Nupkg sha256: `CredProx`
  `2771228a996579cce334ec47821ae126ffa30bde34d1d2a59b2eb0b90192f91d`,
  `CredProx.Abstractions`
  `d7604524302dc463b053fcf1851c9f017456f0dedad6920150a66b73bcb1f74f`,
  `CredProx.AzureKeyVault`
  `71110f21b5092fb6b3b9799606c80974a983b06f43395961d91961dfb9147c18`,
  `CredProx.Testing`
  `78950e95c94775e8e5eebb04fcb60e20c53e3ed8001ade9d179f29a9e28a337f`. Consumer verify:
  http-cache cleared, out-of-repo scratch project (the repo-level source mapping pins
  `CredProx*` to the local feed, so an in-tree restore cannot prove the registry),
  isolated package cache, all four downloads byte-identical to the pushed artifacts,
  `samples/QuickStart` smoke green on those exact bytes (WireMock journal shows the
  credential attached; the caller's echo shows it redacted). GitHub: ONE squashed
  commit on the previous public tip, noreply identity — a regular append, no collapse,
  no tag deletions; CI green (Actions run 42884590564). The benchmark baseline was
  refreshed from a second full pass at the release commit (`baselines/0.9.2/`,
  MACHINE.md records the noisier pass: FAIL=0 WARN=4, all four timing-only, both SSE
  arms inflated together; allocations at or below `0.9.1` siblings).
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
