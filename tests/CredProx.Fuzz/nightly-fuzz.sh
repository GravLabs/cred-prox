#!/bin/bash
# Time-boxed nightly fuzz pass for ONE target (plan §5.4; owner 2026-11-16, extended
# 2026-11-18: the nightly must actually fuzz, prove it fuzzed, and keep any crashing
# input). Run by the Nightly workflow once per matrix target, and runnable as-is:
#   bash tests/CredProx.Fuzz/nightly-fuzz.sh scrub
# Env: FUZZ_SECONDS (time-box per target, default 240), IMAGE, FINDINGS_DIR.
#
# A target PASSES only if all of these hold, and every line below prints its measure:
#   - afl reached its time-box (the FUZZSPIKE-DONE marker): its absence means afl was
#     killed early - a hung exec past -t, OOM, or an instrumented-binary fault;
#   - execs_done > 0 and edges_found > 0 (the coverage edges afl grew): a
#     target that recorded zero of either never really ran - the documented shape is
#     a swallowed startup exception, which fuzzes "green" over a dead harness;
#   - no crash or hang file: either one fails the pass. The input stays on disk under
#     .fuzz-nightly-findings/<target>/default/{crashes,hangs}/ and the workflow's
#     upload-artifact step ships those files by name; the lines below name them too,
#     including into $GITHUB_STEP_SUMMARY when that exists.
# No set -e: every check must run and print, and the exit code is the result.
set -u
cd "$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="${1:?usage: nightly-fuzz.sh <target>}"
BUDGET="${FUZZ_SECONDS:-240}"
IMAGE="${IMAGE:-credprox-fuzz-spike:1}"
FINDINGS="${FINDINGS_DIR:-$PWD/.fuzz-nightly-findings/$TARGET}"

# The container writes this tree as root, so the host rm cannot clear it on a
# re-run: measured 2026-11-18, a second pass in the same tree printed 55 then
# 53 "rm: cannot remove ... Permission denied" lines (root-owned CONTENT) and
# part of the root-owned tree persisted - stale crash inputs could survive into
# the next pass and be counted by it. Clear the access bits from the container
# side first (same shape as the a+rX after the run below), then the host
# pre-clean is real. Mount and chmod the PARENT of the findings dir, never the
# dir itself: where the findings tree was bootstrapped by docker's own
# bind-mount creation the per-target top dir is root:root, and its PARENT sits
# outside a $FINDINGS-level mount, so that mount never reached it. Measured
# 2026-11-18 on such a container-created tree: top dir root:root 777 with the
# parent root:root 755, and every pass printed exactly one residual
# "rm: cannot remove '.../<target>': Permission denied" (unlinking needs write
# on the parent) while all content denials were already zero. The parent is
# always inside the repo tree; a+rwX on its
# other entries is inert for git (rw bits are untracked, X adds the exec bit
# only to directories or already-executable files).
# NOT the mktemp+trap shape $PUB got: the Nightly workflow uploads
# .fuzz-nightly-findings/<target>/default/{crashes,hangs}/* on failure (its
# if: failure() step), so a trap on EXIT would delete the crash inputs before
# that step could ship them - the fixed path IS the artifact path.
FPARENT="$(dirname "$FINDINGS")"
if [ -d "$FINDINGS" ] && docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker run --rm -v "$FPARENT:/work/findings-parent" --entrypoint chmod "$IMAGE" -R a+rwX /work/findings-parent || true
fi
# If the parent exists but the host cannot write to it, nothing below can
# succeed: the target dir cannot be created, so the script would report a
# result for a fuzz that never ran. The shape is real (measured 2026-11-18):
# docker auto-creates a MISSING bind source as root:root, so binding to the
# parent itself leaves the parent (not just its content) a root-owned
# mountpoint - and the guard above never runs here, because its condition
# needs the target dir, which is absent in exactly this shape. Fail loudly
# with the one command that repairs it, BEFORE any result line and before
# pass.log exists. A writable parent never trips this, whatever owns the
# target dir or however it is modeled.
if [ -d "$FPARENT" ] && [ ! -w "$FPARENT" ]; then
  echo "NIGHTLY-FUZZ-SETUP-FAIL $TARGET findings parent $FPARENT is not writable by $(id -un) (root-owned docker bind-mount bootstrap shape): wipe it with: docker run --rm -v \"$FPARENT:/work/findings-parent\" --entrypoint chmod $IMAGE -R a+rwX /work/findings-parent"
  exit 1
fi
rm -rf "$FINDINGS"
mkdir -p "$FINDINGS"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" -f tests/CredProx.Fuzz/Dockerfile tests/CredProx.Fuzz \
    || { echo "NIGHTLY-FUZZ-FAIL $TARGET image build"; exit 1; }
fi
# A fresh per-run publish dir: dotnet publish never clears its -o, so a fixed
# shared dir lets stale bytes ride into the instrumented tree and lets two
# concurrent runs clobber one another (measured 2026-11-18).
PUB=$(mktemp -d "${TMPDIR:-/tmp}/credprox-fuzzpub.XXXXXX")
trap 'rm -rf "$PUB"' EXIT
dotnet publish tests/CredProx.Fuzz/CredProx.Fuzz.csproj -c Release -o "$PUB" \
  || { echo "NIGHTLY-FUZZ-FAIL $TARGET publish"; exit 1; }

docker run --rm \
  -v "$PUB":/work/publish:ro \
  -v "$PWD/tests/CredProx.Fuzz/corpus/$TARGET:/work/corpus:ro" \
  -v "$PWD/tests/CredProx.Fuzz/spike-in-container.sh:/work/spike.sh:ro" \
  -v "$FINDINGS:/work/findings" \
  -e FUZZ_SECONDS="$BUDGET" \
  "$IMAGE" bash /work/spike.sh "$TARGET" > "$FINDINGS/pass.log" 2>&1
RUN_RC=$?

# The container's exit code is the first fact about the run. Dropping it (measured
# 2026-11-20, fuzz-target audit) made an in-container SPIKE-FAIL -
# e.g. the instrument step refusing an assembly - surface only as done=0 with three
# causes that were not the real one, because a container that dies before afl starts
# looks identical to a run afl had to kill.
if [ "$RUN_RC" != "0" ]; then
  echo "NIGHTLY-FUZZ-FAIL $TARGET fuzz container exited rc=$RUN_RC (pass.log above)"
  SPIKE_FAIL_LINE=$(grep -m1 'SPIKE-FAIL' "$FINDINGS/pass.log" 2>/dev/null || true)
  if [ -n "$SPIKE_FAIL_LINE" ]; then
    echo "NIGHTLY-FUZZ-FAIL $TARGET container reported: $SPIKE_FAIL_LINE"
  else
    echo "NIGHTLY-FUZZ-FAIL $TARGET no SPIKE-FAIL marker in pass.log: the container died outside the spike script (rc=$RUN_RC names it)"
  fi
fi

# The container writes findings as root; upload-artifact runs as the runner user,
# so make the tree (crash inputs included) readable before this step exits.
docker run --rm -v "$FINDINGS:/work/findings" --entrypoint chmod "$IMAGE" -R a+rX /work/findings

STATS="$FINDINGS/default/fuzzer_stats"
# afl++ 5.x names the coverage counter edges_found (afl named it paths_total);
# reading the wrong key would report zero edges on a run that fuzzed fine.
execs=$(grep -m1 '^execs_done' "$STATS" 2>/dev/null | grep -oE '[0-9]+$' || echo 0)
edges=$(grep -m1 '^edges_found' "$STATS" 2>/dev/null | grep -oE '[0-9]+$' || echo 0)
done_marker=$(grep -c "FUZZSPIKE-DONE $TARGET" "$FINDINGS/pass.log" || true)
# Only id:* files are replayable inputs; afl also drops a README.txt next to them.
crashes=$(find "$FINDINGS/default/crashes" -type f -name 'id*' 2>/dev/null | sort || true)
hangs=$(find "$FINDINGS/default/hangs" -type f -name 'id*' 2>/dev/null | sort || true)
crash_count=$(printf '%s' "$crashes" | grep -c . || true)
hang_count=$(printf '%s' "$hangs" | grep -c . || true)

echo "== nightly fuzz $TARGET: execs=${execs:-0} edges=${edges:-0} crashes=$crash_count hangs=$hang_count done=$done_marker budget=${BUDGET}s =="
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "- fuzz \`$TARGET\`: execs=${execs:-0} edges=${edges:-0} crashes=$crash_count hangs=$hang_count done=$done_marker"
    for f in $crashes $hangs; do echo "  - kept input: \`$f\`"; done
  } >> "$GITHUB_STEP_SUMMARY"
fi

fail=0
if [ "$RUN_RC" != "0" ]; then
  echo "NIGHTLY-FUZZ-FAIL $TARGET run failed at the container, not at afl - see the rc line above"
  fail=1
fi
if [ "${done_marker:-0}" != "1" ]; then
  if [ "$RUN_RC" = "0" ]; then
    echo "NIGHTLY-FUZZ-FAIL $TARGET afl never reached its time-box (killed, OOM, or exec overrun)"
  else
    echo "NIGHTLY-FUZZ-FAIL $TARGET no time-box marker: the container exited rc=$RUN_RC before afl reported DONE"
  fi
  fail=1
fi
if [ "${execs:-0}" -eq 0 ]; then
  echo "NIGHTLY-FUZZ-FAIL $TARGET zero executions recorded (harness never ran a case)"
  fail=1
fi
if [ "${edges:-0}" -eq 0 ]; then
  echo "NIGHTLY-FUZZ-FAIL $TARGET zero coverage edges (swallowed startup exception shape)"
  fail=1
fi
if [ "$crash_count" -gt 0 ]; then
  echo "NIGHTLY-FUZZ-FAIL $TARGET crash inputs kept:"
  printf '  %s\n' $crashes
  fail=1
fi
if [ "$hang_count" -gt 0 ]; then
  echo "NIGHTLY-FUZZ-FAIL $TARGET hang inputs kept:"
  printf '  %s\n' $hangs
  fail=1
fi
if [ "$fail" = "0" ]; then
  echo "NIGHTLY-FUZZ-PASS $TARGET execs=${execs:-0} edges=${edges:-0}"
fi
exit "$fail"
