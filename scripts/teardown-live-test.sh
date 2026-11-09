#!/usr/bin/env bash
# Teardown for the M26 live Azure/Entra test resources (docs/azure-live-test-plan.md).
#
# Deletes ONLY the credprox-* named objects the live smokes create:
#   - the resource group credprox-live-test (with the user-assigned identity and
#     the Key Vault inside it, and the RBAC assignments scoped to it),
#   - the three Entra app registrations by display name (app registrations are
#     tenant-wide, not RG-scoped, so they are deleted explicitly).
#
# Nothing else is touched: every lookup is by the exact credprox-* name, and a
# name that resolves to nothing is reported and skipped.
#
# Usage:
#   scripts/teardown-live-test.sh --dry-run   # show what exists and would go
#   scripts/teardown-live-test.sh             # delete it (prompts per object)
set -euo pipefail

RG=credprox-live-test
APPS=(credprox-e5-oauth credprox-e14-api credprox-e14-client)

dry=0
case "${1:-}" in
  --dry-run) dry=1 ;;
  "") ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

command -v az >/dev/null || { echo "az CLI not installed - nothing to tear down here." >&2; exit 0; }

if ! az account get-access-token -o none >/dev/null 2>&1; then
  echo "not signed in to az - nothing to tear down from this machine."
  exit 0
fi

echo "== App registrations (tenant-wide; deleted by exact display name) =="
for name in "${APPS[@]}"; do
  ids=$(az ad app list --display-name "$name" --query '[].appId' -o tsv 2>/dev/null || true)
  if [[ -z "$ids" ]]; then
    echo "  $name: absent"
    continue
  fi
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    if [[ "$dry" == 1 ]]; then
      echo "  $name: present (would delete)"
    else
      read -r -p "  delete app registration $name (appId ***? [y/N] " ok
      [[ "$ok" == y ]] && az ad app delete --id "$id" && echo "  $name: deleted"
    fi
  done <<< "$ids"
done

echo "== Resource group $RG (identity, vault, and its RBAC die with it) =="
if az group exists -n "$RG" | grep -qx true; then
  if [[ "$dry" == 1 ]]; then
    echo "  present (would delete, including resources inside)"
    az resource list -g "$RG" --query '[].name' -o tsv | sed 's/^/    - /' || true
  else
    read -r -p "  delete resource group $RG with everything inside? [y/N] " ok
    [[ "$ok" == y ]] && az group delete -n "$RG" --yes && echo "  deleted"
  fi
else
  echo "  absent"
fi

# Class-wide net (finding 2026-11-04): the fixed list missed one-off wiring
# scratch (m4-*, pc-body, devicecode logs). Anything named /tmp/credprox-* is
# test scratch by convention and goes; Markdown notes (recaps, handover
# bodies) are kept - those are seats' durable records, not teardown's to eat.
# The battery's own scratch never lands here: its EXIT trap removes it.
# Boundary (review F3): the .md keep matches TOP-LEVEL /tmp/credprox-*.md
# only - a note nested inside a scratch directory is swept with the directory,
# so keep local notes as top-level files.
echo "== Local scratch (/tmp/credprox-* test scratch) =="
shopt -s nullglob
for f in /tmp/credprox-*; do
  if [[ "$f" == *.md ]]; then
    echo "  $f: kept (local note - not deleted here)"
    continue
  fi
  if [[ "$dry" == 1 ]]; then
    echo "  $f: present (would remove)"
  else
    rm -rf "$f" && echo "  $f: removed"
  fi
done

echo
if [[ "$dry" == 1 ]]; then echo "Dry run complete: nothing was deleted."; fi
echo "Re-run scripts/live-azure-smoke.sh afterwards: with the objects gone every"
echo "phase SKIPs or reports its precondition."
