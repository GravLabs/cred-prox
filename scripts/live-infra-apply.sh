#!/usr/bin/env bash
# M26 Phase 5 one-command APPLY for the RG-scoped live-validation infra
# (infra/azure/credprox-live.bicep): the credprox-live-kv vault + the owner's
# Key Vault Secrets Officer assignment. Idempotent.
#
# Soft-delete recovery: destroy purges, but an interrupted destroy can leave
# the vault soft-deleted - and a same-name create is then name-locked - so
# recover first when that's the state (plan Phase 5 decision).
# Person-present scope: deploys into the person's subscription.
set -euo pipefail
cd "$(dirname "$0")/.."
RG=credprox-live-test
VAULT=credprox-live-kv

[[ "$(az account get-access-token -o none 2>/dev/null; echo $?)" == 0 ]] \
  || { echo "az sign-in required (person-present)"; exit 1; }
az group show -n "$RG" -o none 2>/dev/null \
  || { echo "resource group $RG absent - create it person-present first"; exit 1; }

if ! az keyvault show -n "$VAULT" -g "$RG" -o none 2>/dev/null \
   && az keyvault show-deleted -n "$VAULT" -o none 2>/dev/null; then
  echo "recovering soft-deleted vault $VAULT"
  az keyvault recover -n "$VAULT" -o none
fi

PRINCIPAL=$(az ad signed-in-user show --query id -o tsv)
# Role definition id resolved live - never hardcoded (a recalled GUID caused a
# failed deployment 2026-11-04; the API is the only source of truth).
ROLE_ID=$(az role definition list --name 'Key Vault Secrets Officer' --query "[0].name" -o tsv)
[[ -n "$ROLE_ID" ]] || { echo "Secrets Officer role definition not found"; exit 1; }
az deployment group create -g "$RG" \
  --template-file infra/azure/credprox-live.bicep \
  --parameters officerPrincipalId="$PRINCIPAL" officerRoleId="$ROLE_ID" -o none
echo "applied: $VAULT + Secrets Officer assignment (resolved live) in $RG"
