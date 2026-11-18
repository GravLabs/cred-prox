#!/usr/bin/env python3
"""Enforce the coverage gates from docs/credprox-plan.md §5.3.

Parses coverlet Cobertura XML, aggregates per-assembly line and branch
counts across all matched coverage files, and fails when a gated assembly
is below its gate. When several test projects instrument the same assembly
(unit + security), coverage is the UNION: a line or branch counts as covered
if any run covered it — summing per-file counts would average the runs down.

Gates (§5.3):
  CredProx (core)          line >= 90%, branch >= 80%
  every other src package  line >= 80%

Presence is required for EVERY package under src/: the standard battery
instrumented all of them as of the slice-4 era, so a package missing from the
coverage data means a dropped XML or dropped wiring and fails by name — there
is no "not required yet" SKIP. The checked list is derived from src/*/ so a
new package cannot hide by being forgotten below; its rates default to
DEFAULT_RATES until listed.

Usage: coverage-gate.py [GLOB ...]  (default: TestResults/**/coverage.cobertura.xml)
Exit codes: 0 all gates met, 1 a gate failed, 2 no coverage file found.
"""
import glob
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

# assembly -> (min line rate, min branch rate or None); every src package is
# also required to appear (see the docstring).
GATE_RATES = {
    "CredProx": (0.90, 0.80),
    "CredProx.Abstractions": (0.80, None),
    "CredProx.Testing": (0.80, None),
    "CredProx.AzureKeyVault": (0.80, None),
    "CredProx.CallerTokens": (0.80, None),
    "CredProx.CallerKeys": (0.80, None),
    "CredProx.Hmac": (0.80, None),
    "CredProx.LoginExchange": (0.80, None),
    "CredProx.OAuth": (0.80, None),
}
DEFAULT_RATES = (0.80, None)


def gated_assemblies():
    """Rate-listed assemblies plus every project package under src/."""
    src = pathlib.Path(__file__).resolve().parents[1] / "src"
    found = {p.parent.name for p in src.glob("*/*.csproj")}
    return sorted(set(GATE_RATES) | found)

COND = re.compile(r"\((\d+)/(\d+)\)")


def main(argv):
    patterns = argv[1:] or ["TestResults/**/coverage.cobertura.xml"]
    files = sorted({f for p in patterns for f in glob.glob(p, recursive=True)})
    if not files:
        print(f"coverage-gate: no coverage file matched {patterns}", file=sys.stderr)
        return 2

    gates = gated_assemblies()

    # Union across files: (assembly, class, line-number) -> covered in any run.
    line_cov = {}    # asm -> {key: bool}
    branch_cov = {}  # asm -> {key: (total_branches, max covered)}
    seen = set()
    for path in files:
        for pkg in ET.parse(path).getroot().iter("package"):
            asm = pkg.get("name")
            if asm not in gates:
                continue
            seen.add(asm)
            lc = line_cov.setdefault(asm, {})
            bc = branch_cov.setdefault(asm, {})
            for cls in pkg.iter("class"):
                lines_el = cls.find("lines")  # class-level lines only; method-level ones duplicate them
                if lines_el is None:
                    continue
                cls_name = cls.get("name")
                for line in lines_el.findall("line"):
                    key = (cls_name, line.get("number"))
                    covered = int(line.get("hits", "0")) > 0
                    lc[key] = lc.get(key, False) or covered
                    if line.get("branch") == "True":
                        m = COND.search(line.get("condition-coverage", ""))
                        if m:
                            total, cov = int(m.group(2)), int(m.group(1))
                            prev = bc.get(key)
                            bc[key] = (total, max(cov, prev[1])) if prev else (total, cov)

    totals = {}
    for asm in gates:
        lc = line_cov.get(asm, {})
        bc = branch_cov.get(asm, {})
        totals[asm] = [
            len(lc), sum(1 for v in lc.values() if v),
            sum(t for t, _ in bc.values()), sum(c for _, c in bc.values()),
        ]

    failed = False
    for asm in gates:
        min_line, min_branch = GATE_RATES.get(asm, DEFAULT_RATES)
        lines, covered, branches, cov_branches = totals[asm]
        if asm not in seen:
            print(f"FAIL {asm}: no coverage data (every src package must be instrumented)",
                  file=sys.stderr)
            failed = True
            continue
        line_rate = covered / lines if lines else 1.0
        branch_rate = cov_branches / branches if branches else 1.0
        problems = []
        if line_rate < min_line:
            problems.append(f"line {line_rate:.1%} < {min_line:.0%}")
        if min_branch is not None and branch_rate < min_branch:
            problems.append(f"branch {branch_rate:.1%} < {min_branch:.0%}")
        detail = f"line {line_rate:.1%} ({covered}/{lines})"
        if min_branch is not None:
            detail += f", branch {branch_rate:.1%} ({cov_branches}/{branches})"
        if problems:
            print(f"FAIL {asm}: {'; '.join(problems)} [{detail}]", file=sys.stderr)
            failed = True
        else:
            print(f"ok   {asm}: {detail}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
