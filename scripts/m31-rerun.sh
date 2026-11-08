#!/bin/bash
# M31 verification rerun (plan §5.4). Plain commands, NO pipefail — each step prints its
# own RC and a tail of the interesting lines; the caller reads the markers.
#
# Sections: [1] solution build  [2] fuzz-harness build-only rot check  [3] test suites
# (CI per-project form)  [4] coverage gates (§5.3)  [5] mutation spot-rerun (per area,
# opt-in)  [6] fuzz batch (manual, see tests/CredProx.Fuzz/run-targets.sh).
# Mutation and fuzz RUNS stay out of CI by ruling; [2] is build-only on purpose:
# tests/CredProx.Fuzz lives OUTSIDE CredProx.slnx, so the [1] solution build never
# compiles it and nothing else catches harness rot between fuzz batches.
cd "$(dirname "$0")/.." || exit 1

echo "== [1] solution build =="
dotnet build CredProx.slnx -c Release --nologo > /tmp/m31-rerun-build.log 2>&1
echo "BUILD-RC-$?"
grep -E "error|Warning\(s\)|Error\(s\)" /tmp/m31-rerun-build.log | tail -3

echo "== [2] fuzz harness build-only (out-of-slnx rot check) =="
dotnet build tests/CredProx.Fuzz/CredProx.Fuzz.csproj -c Release --nologo > /tmp/m31-rerun-fuzzbuild.log 2>&1
echo "FUZZBUILD-RC-$?"
grep -E "error|Error\(s\)" /tmp/m31-rerun-fuzzbuild.log | tail -3

echo "== [3] test suites (CI per-project form) =="
for p in Tests SecurityTests ConformanceTests LoadTests E2ETests; do
  dotnet test "tests/CredProx.$p/CredProx.$p.csproj" -c Release --nologo > "/tmp/m31-rerun-$p.log" 2>&1
  echo "$p-RC-$?"
  grep -E "Passed!|Failed!" "/tmp/m31-rerun-$p.log" | tail -1
done

echo "== [4] coverage gates (§5.3) =="
dotnet test tests/CredProx.Tests/CredProx.Tests.csproj -c Release --nologo \
  --collect:"XPlat Code Coverage" > /tmp/m31-rerun-cov-tests.log 2>&1
echo "COVTESTS-RC-$?"
python3 build/coverage-gate.py "TestResults/**/coverage.cobertura.xml"
echo "COVGATE-RC-$?"

echo "== [5] mutation spot-rerun (opt-in) =="
echo "Per area (fast, settles stale survivors):"
echo "  dotnet stryker --project src/CredProx/CredProx.csproj \\"
echo "    -tp tests/CredProx.Tests/CredProx.Tests.csproj \\"
echo "    -tp tests/CredProx.SecurityTests/CredProx.SecurityTests.csproj \\"
echo "    -tp tests/CredProx.ConformanceTests/CredProx.ConformanceTests.csproj \\"
echo "    --mutate \"**/<Area>/**\"      # glob MUST be **/Dir/** when --project is given"
echo "Full core run (headline score, ~3 h): same command without --mutate."

echo "== [6] fuzz batch =="
echo "tests/CredProx.Fuzz/run-targets.sh (six targets, one pinned core each;"
echo "findings host-mounted; FUZZ_SECONDS budget). Build-only rot check is [2] above."

echo "M31RERUN-DONE"
