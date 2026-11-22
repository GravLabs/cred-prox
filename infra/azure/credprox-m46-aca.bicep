// M46 unit-3 ACA live-validation infrastructure; sibling
// of credprox-live-r2.bicep, whose discipline this mirrors line for line - read that
// file for the WHY behind each shape: purge protection OMITTED, the inert kubelet
// identity on the environment, BCP120 guid names, Americas-only regions).
// One-command apply + destroy: scripts/live-m46-aca.sh apply|destroy (the lead runs
// every live Azure step). Unlike M29, destroy DELETES this whole resource group and
// read-backs az group exists = false - the M46 row demands RG-gone, where M29
// deliberately kept the RG (live-infra-destroy-r2.sh header). Disclosed divergence.
// The app ships via scripts/live-m46-aca.sh deploy as the SHIPPED
// samples/AzureContainerApps host + its shipped StubApi co-located (one ACA app,
// two containers - the sample's vendor destination is http://localhost:8098, and
// containers in one app share the network namespace, so the shipped config needs
// no edit). Verification ships as an in-environment job running the harness
// acacheck mode. No app registrations live here. Carries names only - no secrets,
// no GUIDs: every role definition id and the officer principal id are parameters
// the apply step resolves live (recalled role ids have bitten before - M26).
targetScope = 'resourceGroup'
@description('RG home region for the Container Apps environment, ACR - and the vault (all one region). Americas regions ONLY, same decision and fallback order as round 2: default eastus, fallback eastus2, centralus, westus2, southcentralus, canadacentral.')
param mainLocation string
@description('Name of the M46 ACA live-validation Key Vault.')
param vaultName string = 'credprox-m46-kv'
@description('Vault location: the SAME region as everything else (Americas only, round-2 decision). The apply step passes this explicitly and destroy purges with the same value.')
param vaultLocation string = 'eastus'
@description('User-assigned managed identity the container app and the verify job run as: reads the vault (vendor key + caller-key hash) through it - the managed-identity-to-vault path under proof.')
param uaiName string = 'credprox-m46-uai'
@description('Separate kubelet identity used only for ACR image pulls - identity separation between image plane and app runtime (round-2 shape).')
param kubeletName string = 'credprox-m46-kubelet'
@description('Container image registry (Basic SKU).')
param acrName string = 'credproxm46reg'
@description('Container Apps environment (Consumption).')
param envName string = 'credprox-m46-env'
@description('Principal id that gets Key Vault Secrets Officer on the vault (the material step writes the two vault secrets through the signed-in az identity). A principal id, not a secret.')
param officerPrincipalId string
@description('Role definition id for Key Vault Secrets Officer - resolved live by the apply step (az role definition list --name). No GUID lives in the tree.')
param officerRoleId string
@description('Role definition id for "Key Vault Secrets User" - resolved live. Granted to the app UAI on THIS vault only. (Named without the word "secret" so the bicep linter does not flag a role definition id as a secret parameter.)')
param vaultUserRoleDefinitionId string
@description('Role definition id for AcrPull - resolved live. Granted to the kubelet identity on THIS registry only.')
param acrPullRoleId string
resource uai 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: uaiName
  location: mainLocation
}
resource kubelet 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: kubeletName
  location: mainLocation
}
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: vaultLocation
  properties: {
    createMode: 'default'
    enableRbacAuthorization: true
    // Soft-delete cannot be disabled; destroy purges so apply starts clean.
    softDeleteRetentionInDays: 7
    // purge protection: OMITTED, which is how "off" is expressed - an explicit
    // false is rejected by the Key Vault API on every subscription (M26 apply
    // failure), and true is irreversible, so never set it here. Off keeps
    // destroy's purge - and with it the one-command cycle - possible.
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
  }
}
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: mainLocation
  sku: {
    name: 'Basic'
  }
  properties: {
    // pull happens through the kubelet identity + AcrPull, not a static admin
    // password: nothing here is a credential.
    adminUserEnabled: false
  }
}
resource env 'Microsoft.App/managedEnvironments@2024-02-02-preview' = {
  name: envName
  location: mainLocation
  // Inert, same as round 2: environment-level identity does not activate image
  // pull (live finding 2026-11-06 - no kubeletIdentity on managedEnvironments;
  // the APP and JOB attach the kubelet identity and select it via
  // configuration.registries[].identity). Kept so re-apply stays a no-op.
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${kubelet.id}': {}
    }
  }
  properties: {
    // Consumption profile (default): no workloadProfiles, no Log Analytics.
    zoneRedundant: false
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
// roleAssignment NAMES may only use start-computable properties (BCP120).
resource uaiVaultUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, uai.id, vaultUserRoleDefinitionId)
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', vaultUserRoleDefinitionId)
    principalId: uai.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource kubeletAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, kubelet.id, acrPullRoleId)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: kubelet.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
output vaultUri string = vault.properties.vaultUri
output uaiClientId string = uai.properties.clientId
output uaiPrincipalId string = uai.properties.principalId
output acrLoginServer string = acr.properties.loginServer
