#!/bin/bash
# M31 spike + Phase B runner (plan 5.4): instrument the published harness inside the pinned
# AFL++ container and run afl-fuzz against ONE target (argv: pathpatterns | headerattach |
# scrub | sse | configkeys | parsers; default pathpatterns; legacy `canary` = pathpatterns
# seeded-violation mode). Quick rot check without any fuzzing (the nightly fuzz-build job
# runs exactly this; the project is outside CredProx.slnx so the solution build never sees it):
#   dotnet build tests/CredProx.Fuzz/CredProx.Fuzz.csproj -c Release
# Host side publish before the container steps:
#   dotnet publish tests/CredProx.Fuzz/CredProx.Fuzz.csproj -c Release -o /tmp/fuzzpub
# Then, from the repo root (per-target corpus mounted at /work/corpus):
#   docker build -t credprox-fuzz-spike:1 -f tests/CredProx.Fuzz/Dockerfile tests/CredProx.Fuzz
#   docker run --rm \
#     -v /tmp/fuzzpub:/work/publish:ro \
#     -v $PWD/tests/CredProx.Fuzz/corpus/pathpatterns:/work/corpus:ro \
#     -v $PWD/tests/CredProx.Fuzz/spike-in-container.sh:/work/spike.sh:ro \
#     -e FUZZ_SECONDS=7200 \
#     credprox-fuzz-spike:1 bash /work/spike.sh pathpatterns
# For the six-target parallel batch use run-targets.sh (pins one core per container).
#
# afl-fuzz knobs: AFL_SKIP_BIN_CHECK=1 is required — the target binary is the plain
# `dotnet` host; the instrumented code is the managed CredProx.dll it loads. The
# DOTNET_TieredCompilation/ReadyToRun pair keeps the CLR from bypassing the injected
# instrumentation hooks. -t 10000+ (plus = tolerate slow first execs): a cold dotnet
# start under heavy host load overran the old 5s limit and afl misreported the dry-run
# timeout as 'No instrumentation detected'. Crash inputs are hex-dumped to stdout as a
# convenience for unmounted runs; batch runs mount /work/findings from the host so the
# findings survive even if afl is killed before the dump section runs.
set -e
cd /work
TARGET="${1:-pathpatterns}"
CANARY=""
if [ "$TARGET" = canary ]; then
  TARGET=pathpatterns
  CANARY=canary
fi
cp -r publish instr
sharpfuzz instr/CredProx.dll
echo "== instrumented =="
mkdir -p findings
# afl-fuzz only reads the input directory, so the read-only /work/corpus mount is used
# directly — copying it onto itself (same mount point) fails since the corpus shares
# the path, and afl never writes into -i anyway.
export DOTNET_TieredCompilation=0 DOTNET_ReadyToRun=0 AFL_SKIP_BIN_CHECK=1
if [ -n "$CANARY" ]; then
  AFL_BENCH_UNTIL_CRASH=1 timeout 120 afl-fuzz -i /work/corpus -o findings -t 10000+ -- dotnet instr/CredProx.Fuzz.dll "$TARGET" canary || true
else
  timeout "${FUZZ_SECONDS:-60}" afl-fuzz -i /work/corpus -o findings -t 10000+ -- dotnet instr/CredProx.Fuzz.dll "$TARGET" || true
fi
echo "== stats =="
grep -E "execs_done|execs_per_sec|paths_total|unique_crashes|unique_hangs" findings/*/fuzzer_stats || true
ls findings/default/crashes/ 2>/dev/null || echo "(no crashes)"
for f in findings/default/crashes/id*; do
  [ -e "$f" ] || continue
  echo "== crash input $f =="
  od -An -tx1 "$f" | head -30
done
echo "FUZZSPIKE-DONE $TARGET"
