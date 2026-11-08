#!/bin/bash
# M31 Phase B batch driver (plan 5.4): six fuzz targets in parallel, one pinned core
# each, FUZZ_SECONDS budget per target (default 7200). Core plan on a 20-core host:
# fuzz takes 2-7, 0-1 stay free for the system, 8-19 stay free for builds and mutation.
# NO pipefail. Logs land in /tmp/m31-fuzz-<target>.log. Findings (crashes +
# fuzzer_stats) are mounted from a host directory — afl writes them continuously —
# so a killed or docker-hung batch cannot eat findings a second time (the first
# batch lost both crashes to --rm + an early kill and only recovered them by
# docker cp off live containers). Fresh findings dir per batch: afl refuses a
# non-empty -o directory.
set -e
REPO="${REPO:-$PWD}"
TARGETS=(pathpatterns headerattach scrub sse configkeys parsers)
CORES=(2 3 4 5 6 7)
BUDGET="${FUZZ_SECONDS:-7200}"
FINDINGS="${FINDINGS_DIR:-/tmp/m31-fuzz-findings}"

cd "$REPO"
dotnet publish tests/CredProx.Fuzz/CredProx.Fuzz.csproj -c Release -o /tmp/fuzzpub

rm -rf "$FINDINGS"
mkdir -p "$FINDINGS"
i=0
for t in "${TARGETS[@]}"; do
  core=${CORES[$i]}
  mkdir -p "$FINDINGS/$t"
  docker run --rm --name "m31-fuzz-$t" \
    -v /tmp/fuzzpub:/work/publish:ro \
    -v "$REPO/tests/CredProx.Fuzz/corpus/$t:/work/corpus:ro" \
    -v "$REPO/tests/CredProx.Fuzz/spike-in-container.sh:/work/spike.sh:ro" \
    -v "$FINDINGS/$t:/work/findings" \
    -e FUZZ_SECONDS="$BUDGET" \
    --entrypoint taskset \
    credprox-fuzz-spike:1 -c "$core" bash /work/spike.sh "$t" \
    > "/tmp/m31-fuzz-$t.log" 2>&1 &
  i=$((i + 1))
done
wait

echo "== per-target summary =="
for t in "${TARGETS[@]}"; do
  stats=$(grep -hE "execs_done|paths_total|unique_crashes|unique_hangs" "/tmp/m31-fuzz-$t.log" | tr -d ' ' | tr '\n' ' ' || true)
  crashes=$(grep -c "crash input" "/tmp/m31-fuzz-$t.log" || true)
  done_marker=$(grep -c "FUZZSPIKE-DONE" "/tmp/m31-fuzz-$t.log" || true)
  echo "$t | done=$done_marker | crash_inputs=$crashes | ${stats:-no stats}"
done
echo "findings (live even if a run was killed): $FINDINGS/<target>/default/{fuzzer_stats,crashes}"
echo "FUZZALL-DONE"
