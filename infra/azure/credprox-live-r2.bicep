// M29 round-2 live-validation infrastructure (docs/azure-live-test-plan.md,
// Round 2 R2.1). Extends the M26 template (credprox-live.bicep) with the
// inside-Azure surface: user-assigned managed identity, Container Apps
// environment, ACR, and the three single-scope RBAC assignments.
// One-command apply: scripts/live-infra-apply-r2.sh
// One-command destroy: scripts/live-infra-destroy-r2.sh
// The Container APP ships via scripts/live-m29-deploy-app.sh (CLI ergonomics;
// decision recorded in the plan). No app registrations exist in round 2 - the
// paired-Entra script of round 1 does not apply (UAI is an ARM resource in
// this RG). Carries names only - no secrets, no GUIDs: every role definition
// id and the officer principal id are parameters the apply script resolves
// live (recalled role ids have bitten before - M26).
targetScope = 'resourceGroup'

@description('RG home region for the Container Apps environment, ACR - and the vault (all one region). Decision 2026-11-06: Americas regions ONLY; default eastus, fallback order eastus2, centralus, westus2, southcentralus, canadacentral (plan §Region; live what-if 2026-11-06 passed all six, westeurope still rejected). The tenant denyLocation policy remains unreadable from the maintainer account and RG-scope policy remains the one thing what-if cannot evaluate.')
param mainLocation string

@description('Name of the round-2 live-validation Key Vault.')
param vaultName string = 'credprox-m29-kv'

@description('Vault location: the SAME region as everything else (decision 2026-11-06, Americas only). The round-1 northeurope Key Vault RP exemption is moot - the 2026-11-06 Americas what-if never flagged the vault. The apply script passes this explicitly and destroy purges with the same value.')
param vaultLocation string = 'eastus'

@description('User-assigned managed identity the container app runs as (the M29 subject: a REAL UAI identity for CredProx egress).')
param uaiName string = 'credprox-m29-uai'

@description('Separate kubelet identity used by the Container Apps environment only for ACR image pulls - identity separation between image plane and app runtime.')
param kubeletName string = 'credprox-m29-kubelet'

@description('Container image registry (Basic SKU).')
param acrName string = 'credproxm29reg'

@description('Container Apps environment (Consumption).')
param envName string = 'credprox-m29-env'

@description('Principal id that gets Key Vault Secrets Officer on the vault (material scripts write through the signed-in az identity). A principal id, not a secret.')
param officerPrincipalId string

@description('Role definition id for Key Vault Secrets Officer - resolved live by the apply script (az role definition list --name). No GUID lives in the tree.')
param officerRoleId string

@description('Role definition id for "Key Vault Secrets User" - resolved live by the apply script. Granted to the app UAI on THIS vault only. (Named without the word "secret" so the bicep linter does not flag a role definition id as a secret parameter.)')
param vaultUserRoleDefinitionId string

@description('Role definition id for AcrPull - resolved live by the apply script. Granted to the kubelet identity on THIS registry only.')
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
    // Soft-delete cannot be disabled; destroy purges so apply starts clean
    // (round-1 Phase 5 decision).
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
  // The kubelet UAI (below) is the identity that HOLDS AcrPull (scoped to our
  // registry). It is NOT consumed here: environment-level identity does not
  // activate image pull - managedEnvironments has no kubeletIdentity property
  // (live finding 2026-11-06: az bicep build warns BCP037 on it, the live env
  // reads it back null, and pull went UNAUTHORIZED with this assignment in
  // place). The APP and the battery JOB attach this identity and select it via
  // configuration.registries[].identity (docs: managed-identity-image-pull).
  // The assignment here is kept inert: the live env already has it, re-apply
  // stays a no-op, and the step-9 destroy->rebuild cycle proves this shape.
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      // quoted-interpolation key form: bicep 0.46.1 (the az-bundled compiler
      // here) parses this, not the bare (expr) form.
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

// roleAssignment NAMES may only use start-computable properties (BCP120) -
// hence guid over .id (deterministic per pair), while principalId itself is a
// runtime reference.
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
