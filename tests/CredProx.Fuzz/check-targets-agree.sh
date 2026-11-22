#!/usr/bin/env bash
# Fuzz target names have three homes (fuzz-target audit unit 3, 2026-11-20):
# the Program.cs dispatch labels, run-targets.sh TARGETS, and the Nightly workflow
# matrix. A drift is silent by construction: a matrix name with no dispatch case
# makes afl fork a harness that exits(1) on the unknown target - the crash class the
# nightly already reds on, but blamed on the fuzzed code; a run-targets.sh name with
# no matrix entry just never runs in CI. This check fails when the three sets disagree,
# naming each side's extras. Witness: renaming any one target in one home reddens it.
# Runnable standalone and from run-targets.sh; the Nightly workflow runs it first.
set -u
cd "$(cd "$(dirname "$0")/../.." && pwd)"

PROG=tests/CredProx.Fuzz/Program.cs
RUNNER=tests/CredProx.Fuzz/run-targets.sh
WORKFLOW=.github/workflows/nightly.yml

# Dispatch labels: the case arms of the target switch, up to its default arm.
prog=$(awk '/switch \(target\)/,/default:/' "$PROG" | grep -oE 'case "[a-z]+"' | sed 's/case "//; s/"//' | sort)
# Batch driver list: TARGETS=(...)
runner=$(sed -n 's/^TARGETS=(\(.*\))/\1/p' "$RUNNER" | tr ' ' '\n' | sort)
# Nightly matrix row: target: [a, b, c]
matrix=$(sed -n 's/^\( *\)target: \[\(.*\)\]/\2/p' "$WORKFLOW" | tr ',' '\n' | tr -d ' ' | sort)

fail=0
for name in prog runner matrix; do
  eval "list=\$$name"
  [ -n "$list" ] || { echo "CHECK-TARGETS-FAIL empty extraction from $name (its source line moved: fix the extractor, do not skip the check)"; fail=1; }
done
[ "$fail" = "0" ] || exit 1

if [ "$prog" != "$runner" ] || [ "$prog" != "$matrix" ]; then
  echo "CHECK-TARGETS-FAIL the three fuzz target homes disagree:"
  echo "-- only in Program.cs dispatch:"; comm -23 <(printf '%s\n' "$prog") <(printf '%s\n' "$runner" | sort -u | comm -12 - <(printf '%s\n' "$matrix" | sort -u))
  echo "-- only in run-targets.sh:";      comm -23 <(printf '%s\n' "$runner") <(printf '%s\n' "$prog")
  echo "-- only in nightly.yml matrix:";  comm -23 <(printf '%s\n' "$matrix") <(printf '%s\n' "$prog")
  echo "-- missing from run-targets.sh:"; comm -13 <(printf '%s\n' "$runner") <(printf '%s\n' "$prog")
  echo "-- missing from nightly.yml matrix:"; comm -13 <(printf '%s\n' "$matrix") <(printf '%s\n' "$prog")
  exit 1
fi
echo "CHECK-TARGETS-OK $(printf '%s ' $prog)"
