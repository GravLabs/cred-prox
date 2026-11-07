// M26 live-validation infrastructure (docs/azure-live-test-plan.md Phase 5).
// Decision 2026-10-31: Bicep over Terraform; the Entra app registration
// lives OUTSIDE Bicep (tenant-wide) in scripts/live-e5-app.sh.
// One-command apply: scripts/live-infra-apply.sh   One-command destroy: scripts/live-infra-destroy.sh
// Carries names only - no secrets, no human-principal GUIDs (the officer principal
// is a parameter the apply script resolves from the signed-in az identity).
targetScope = 'resourceGroup'

@description('Name of the live-validation Key Vault.')
param vaultName string = 'credprox-live-kv'

@description('Vault location. NOT the RG home region on purpose: this tenant\'s location policy rejects vault creation there (live-validation-report.md, tenant finding 1).')
param vaultLocation string = 'northeurope'

@description('Principal id that gets Key Vault Secrets Officer on the vault (the E5 run reads vault secrets through the caller identity). A principal id, not a secret.')
param officerPrincipalId string

@description('Role definition id for Key Vault Secrets Officer, resolved live by the apply script (az role definition list --name). No GUID lives in the tree - recalled role ids have bitten before.')
param officerRoleId string

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: vaultLocation
  properties: {
    createMode: 'default'
    enableRbacAuthorization: true
    // Soft-delete cannot be disabled; destroy purges so apply starts clean
    // (see the Phase 5 soft-delete decision in azure-live-test-plan.md).
    softDeleteRetentionInDays: 7
    // purge protection: OMITTED, which is how "off" is expressed - an explicit
    // false is rejected by the Key Vault API on every subscription, and true
    // is irreversible, so never set it here. Off keeps destroy's purge (and
    // with it the one-command cycle) possible.
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
  }
}

resource secretsOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, officerPrincipalId, officerRoleId)
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', officerRoleId)
    principalId: officerPrincipalId
    principalType: 'User'
  }
}

output vaultUri string = vault.properties.vaultUri
