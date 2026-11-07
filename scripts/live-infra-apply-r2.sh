#!/usr/bin/env bash
# M29 R2.1 one-command APPLY for the round-2 RG-scoped infra
# (infra/azure/credprox-live-r2.bicep): UAI + kubelet UAI + credprox-m29-kv
# (same region as everything else) + ACR + Container Apps environment + the three single-scope
# RBAC assignments. Idempotent; same discipline as live-infra-apply.sh:
# soft-delete recover-if-deleted first, every role definition id resolved
# LIVE (never a recalled GUID), officer principal from the signed-in identity.
#
# Region: arg 1, default eastus - owner word 2026-11-06: AMERICAS regions only
# (plan §Region; live what-if 2026-11-06 passed eastus/eastus2/centralus/
# westus2/southcentralus/canadacentral). The vault deploys in the SAME region
# (passed explicitly to Bicep). If the RG was created in a fallback region,
# pass that same region here.
# Person-present scope: deploys into the person's subscription.
set -euo pipefail
cd "$(dirname "$0")/.."
RG=credprox-live-test
VAULT=credprox-m29-kv
LOC="${1:-eastus}"

[[ "$(az account get-access-token -o none 2>/dev/null; echo $?)" == 0 ]] \
  || { echo "az sign-in required (person-present)"; exit 1; }
az group show -n "$RG" -o none 2>/dev/null \
  || { echo "resource group $RG absent - create it person-present first (gate step 1)"; exit 1; }

if ! az keyvault show -n "$VAULT" -g "$RG" -o none 2>/dev/null \
   && az keyvault show-deleted -n "$VAULT" -o none 2>/dev/null; then
  echo "recovering soft-deleted vault $VAULT"
  az keyvault recover -n "$VAULT" -o none
fi

PRINCIPAL=$(az ad signed-in-user show --query id -o tsv)
R_OFF=$(az role definition list --name 'Key Vault Secrets Officer' --query '[0].name' -o tsv)
R_USER=$(az role definition list --name 'Key Vault Secrets User' --query '[0].name' -o tsv)
R_ACR=$(az role definition list --name 'AcrPull' --query '[0].name' -o tsv)
for R in "$R_OFF" "$R_USER" "$R_ACR"; do
  [[ -n "$R" ]] || { echo "a role definition (Secrets Officer / Secrets User / AcrPull) was not resolvable live"; exit 1; }
done

az deployment group create -g "$RG" \
  --template-file infra/azure/credprox-live-r2.bicep \
  --parameters mainLocation="$LOC" vaultLocation="$LOC" officerPrincipalId="$PRINCIPAL" \
    officerRoleId="$R_OFF" vaultUserRoleDefinitionId="$R_USER" acrPullRoleId="$R_ACR" \
  -o none

# Read-back (R2.1 pass criteria - properties and scope counts, names only):
az keyvault show -n "$VAULT" -g "$RG" \
  --query '{rbac:properties.enableRbacAuthorization,purge:properties.enablePurgeProtection,retention:properties.softDeleteRetentionInDays}' -o tsv
VSCOPE=$(az keyvault show -n "$VAULT" -g "$RG" --query id -o tsv)
echo "vault-scope role assignments: $(az role assignment list --scope "$VSCOPE" --query 'length(@)' -o tsv) (expected 2: officer + UAI)"
echo "acr sku: $(az acr show -n credproxm29reg -g "$RG" --query sku.name -o tsv) (expected Basic)"
echo "env provisioningState: $(az resource show -g "$RG" -n credprox-m29-env --resource-type Microsoft.App/managedEnvironments --query properties.provisioningState -o tsv)"
echo "applied: round-2 infra in $RG (region $LOC, vault same region; roles resolved live)"
