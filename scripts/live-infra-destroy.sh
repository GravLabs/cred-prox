#!/usr/bin/env bash
# M26 Phase 5 one-command DESTROY for the RG-scoped live-validation infra:
# deletes credprox-live-kv AND purges it. Purge is deliberate (plan Phase 5
# soft-delete decision): a plain delete leaves the name soft-delete-locked, so
# apply could never recreate; recovering instead would silently resurrect the
# old secret history. Purge is irreversible - this destroys the vault and all
# its secret versions, which is exactly what "destroy" promises. The role
# assignment goes with the vault. Pair: scripts/live-infra-apply.sh.
# Run-manually scope; touches nothing outside credprox-live-kv.
set -euo pipefail
RG=credprox-live-test
VAULT=credprox-live-kv

# Idempotent: tolerate already-gone states (destroy may be re-run).
az keyvault delete -n "$VAULT" -g "$RG" -o none 2>/dev/null || true
# purge needs the vault location (same constant as the Bicep default) and
# an elevated RBAC permission - it may be refused. Non-fatal by design, but the
# read-back below states honestly which state we actually left, so the cycle's
# evidence records which re-apply path (create vs recover) was taken.
az keyvault purge -n "$VAULT" -l northeurope -o none 2>/dev/null || true
# Three states, never two: the list-deleted read-back can itself fail (its RBAC
# is separate from delete/purge), and an UNKNOWN state must never print PURGED.
# could-not-verify + a non-zero exit, so a caller's OK marker cannot mask a live
# name lock (post-release item 1, 2026-11-25; the aca destroy carries the shape).
if ! LIST_DELETED_COUNT="$(az keyvault list-deleted --query "[?name=='$VAULT'] | length(@)" -o tsv 2>/dev/null)"; then
  echo "could-not-verify: $VAULT deletion state UNKNOWN - az keyvault list-deleted failed; the name may still be soft-delete-locked (apply must RECOVER, not create)"
  exit 3
elif [[ "$LIST_DELETED_COUNT" == "1" ]]; then
  echo "destroyed: $VAULT deleted but SOFT-DELETED (purge refused or unavailable - apply will RECOVER it)"
else
  echo "destroyed: $VAULT deleted and PURGED (name lock cleared - apply creates fresh)"
fi
