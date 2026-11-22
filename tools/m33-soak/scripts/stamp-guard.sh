#!/usr/bin/env bash
# M33 soak provenance guard: refuse to start a soak whose host image carries
# CredProx library bytes built from a commit other than this checkout's HEAD.
# Same rule as LoadedLibraryStampTests for the sample bins: the segment after the
# LAST '+' of every CredProx*.dll InformationalVersion - and of SoakHost.dll, the
# host binary itself - must equal `git rev-parse HEAD` here. Why it exists: `compose up` reuses an existing image tag without
# rebuilding (no --build), and NuGet hands back an exact-version cache hit without
# re-checking the feed, so a stale credprox-soakhost tag silently runs the
# previous release's bytes (0.14.0 release soak, attempt 1, 2026-11-20: the host
# log carried the pre-M48 library and the fail-closed startup validator refused
# the candidate config — the validator was right, the harness was stale).
# Prints one marker line: STAMP-GUARD-OK or STAMP-GUARD-FAIL (naming the image,
# the expected stamp and every found stamp). Runs before any container starts.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

head_sha="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null)" || {
  echo "STAMP-GUARD-FAIL could not read HEAD (git rev-parse) in $ROOT"; exit 1; }
case "$head_sha" in
  *[!0-9a-f]*) echo "STAMP-GUARD-FAIL HEAD is not hex in $ROOT (got: $head_sha)"; exit 1 ;;
esac
[ "${#head_sha}" -eq 40 ] || {
  echo "STAMP-GUARD-FAIL HEAD is not a 40-char commit (got: $head_sha)"; exit 1; }

expected_version="$(awk -F'[<>]' '/<Version>/{print $3; exit}' "$ROOT/build/Version.props")"
[ -n "$expected_version" ] || {
  echo "STAMP-GUARD-FAIL no <Version> found in $ROOT/build/Version.props"; exit 1; }
expected="${expected_version}+${head_sha}"

# The image the topology will actually run: resolved through compose, so the guard
# inspects the tag `compose up` would start, including when that tag is stale.
image="$(cd "$HERE/compose" && SOAK_RUN_DIR=/stamp-guard-probe docker compose config 2>/dev/null \
  | awk '/^  soakhost:/{f=1; next} f && /^(  )?[^ ]/{f=0} f && $1=="image:"{print $2; exit}')"
[ -n "$image" ] || { echo "STAMP-GUARD-FAIL could not resolve the soakhost image from compose config"; exit 1; }

docker image inspect "$image" >/dev/null 2>&1 || {
  echo "STAMP-GUARD-FAIL image $image is not present locally - nothing to pin."
  echo "  remedy: build it from this tree (see tools/m33-soak/README.md, Before the first run)."
  exit 1; }

# Read the image's library bytes without starting anything: create (never start),
# copy /app out, remove. Extraction lives under build/ (harness-ignored), not /tmp.
mkdir -p "$HERE/build"
tmp="$(mktemp -d "$HERE/build/stamp-guard.XXXXXX")" || { echo "STAMP-GUARD-FAIL mktemp under $HERE/build failed"; exit 1; }
trap 'rm -rf "$tmp"' EXIT
cid="$(docker create --entrypoint true "$image" 2>/dev/null)" || {
  echo "STAMP-GUARD-FAIL docker create failed for $image"; exit 1; }
docker cp "$cid:/app" "$tmp/app" >/dev/null 2>&1
cp_rc=$?
docker rm -f "$cid" >/dev/null 2>&1
[ "$cp_rc" -eq 0 ] || { echo "STAMP-GUARD-FAIL could not copy /app out of $image"; exit 1; }

dlls=()
while IFS= read -r d; do dlls+=("$d"); done < <(find "$tmp/app" -maxdepth 1 \( -name 'CredProx*.dll' -o -name 'SoakHost.dll' \) | sort)
if [ "${#dlls[@]}" -eq 0 ]; then
  echo "STAMP-GUARD-FAIL image $image holds no CredProx*.dll or SoakHost.dll in /app - the guard has nothing to pin; rebuild the image from this tree"
  exit 1
fi

bad=0
for d in "${dlls[@]}"; do
  # The InformationalVersion sits verbatim in the metadata; the deciding segment is
  # the revision id after the LAST '+' (the LoadedLibraryStampTests rule). Raw tokens
  # may carry the blob length-prefix digit, so the DISPLAY can be dirty while the
  # PASS/FAIL compares only 40-hex revisions — a stale dll cannot contain this
  # checkout's commit id as '+<40hex>' by accident.
  found="$(grep -aoE '[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.]*)?\+[0-9a-f]{40}' "$d" | sort -u | tr '\n' ' ')"
  revs=" $(grep -aoE '\+[0-9a-f]{40}([^0-9a-f]|$)' "$d" | cut -c2-41 | sort -u | tr '\n' ' ') "
  case "$revs" in
    *" $head_sha "*) echo "stamp-ok $(basename "$d") rev=$head_sha" ;;
    *) bad=1; echo "STAMP-MISMATCH $(basename "$d"): expected stamp ${expected} (revision ${head_sha}) , found ${found:-NO-STAMP-READABLE}" ;;
  esac
done

if [ "$bad" -ne 0 ]; then
  echo "STAMP-GUARD-FAIL image $image runs CredProx bytes from another commit; this checkout is $head_sha."
  echo "  remedy: from a CLEAN tree at $head_sha pack, publish, then rebuild the image:"
  echo "    for p in src/*/; do dotnet pack \"\$p\" -c Release -o artifacts/packages; done"
  echo "    dotnet publish tools/m33-soak/SoakHost -c Release -o tools/m33-soak/build/publish"
  echo "    docker build -f tools/m33-soak/SoakHost/Dockerfile -t $image ."
  echo "  (a cache hit is never re-checked against a feed, and compose up never rebuilds an existing tag - the stamp is the only cheap detector)"
  exit 1
fi
echo "STAMP-GUARD-OK image=$image expected=$expected dlls=${#dlls[@]}"
