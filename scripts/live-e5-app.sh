#!/usr/bin/env bash
# M26 Phase 5 PAIRED Entra lifecycle for credprox-e5-oauth - deliberately
# OUTSIDE Bicep (owner decision 2026-10-31): app registrations are tenant-wide,
# not RG-scoped.
#
#   create   - register the app, create its service principal (this tenant does
#              NOT auto-provision SPs - live-validation-report.md finding 4),
#              grant Reader on the live-test RG, and reset a fresh 30-day
#              credential piped STRAIGHT into the vault: the value never prints,
#              never enters argv, never touches disk (the Phase 4 owner-word
#              pipe, reused).
#   destroy  - delete the service principal and the app (idempotent).
#
# Person-present script: both verbs mutate the tenant directory.
set -euo pipefail
RG=credprox-live-test
APP=credprox-e5-oauth
VAULT=credprox-live-kv
KVNAME=CredProx--Secrets--graph-client-secret

[[ "$(az account get-access-token -o none 2>/dev/null; echo $?)" == 0 ]] \
  || { echo "az sign-in required (person-present)"; exit 1; }

case "${1:-}" in
create)
  APPID=$(az ad app list --display-name "$APP" --query "[0].appId" -o tsv 2>/dev/null || true)
  [[ -z "${APPID:-}" ]] || { echo "app $APP already exists (destroy first)"; exit 1; }
  APPID=$(az ad app create --display-name "$APP" --query appId -o tsv)
  az ad sp create --id "$APPID" -o none
  SUB=$(az account show --query id -o tsv)
  az role assignment create --assignee "$APPID" --role Reader \
    --scope "/subscriptions/$SUB/resourceGroups/$RG" -o none
  END=$(date -u -d '+30 days' +%Y-%m-%d)
  az ad app credential reset --id "$APPID" --append --display-name credprox-m26-p4 \
    --end-date "$END" --query password -o tsv \
    | tr -d '\n' \
    | az keyvault secret set --vault-name "$VAULT" --name "$KVNAME" --file /dev/stdin -o none
  echo "created: $APP + SP + Reader on $RG + 30d credential piped into $VAULT (end $END)"
  ;;
destroy)
  APPID=$(az ad app list --display-name "$APP" --query "[0].appId" -o tsv 2>/dev/null || true)
  [[ -n "${APPID:-}" ]] || { echo "app $APP absent (idempotent)"; exit 0; }
  SUB=$(az account show --query id -o tsv)
  # Delete the RG Reader grant BEFORE sp/app delete: deleting the SP first
  # orphans the assignment under an 'Unknown' principal (review, 2026-11-04).
  az role assignment delete --assignee "$APPID" --role Reader \
    --scope "/subscriptions/$SUB/resourceGroups/$RG" -o none 2>/dev/null || true
  az ad sp delete --id "$APPID" -o none 2>/dev/null || true
  az ad app delete --id "$APPID" -o none
  echo "destroyed: $APP (role grant + SP + registration)"
  ;;
*)
  echo "usage: $0 create|destroy" >&2
  exit 2
  ;;
esac
