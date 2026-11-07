// Subscription-scoped wrapper for the ROUND-2 template. Its only purpose is
// the OFFLINE gate: `az deployment sub what-if` validates the whole resource
// set without an existing resource group (a group-scoped what-if would first
// need the RG - a mutation we may not perform offline). Not used for the live
// apply, which deploys credprox-live-r2.bicep group-scoped.
targetScope = 'subscription'

param rgName string = 'credprox-live-test'
param mainLocation string
param vaultLocation string = 'eastus'
param officerPrincipalId string
param officerRoleId string
param vaultUserRoleDefinitionId string
param acrPullRoleId string

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: rgName
  location: mainLocation
}

module r2 'credprox-live-r2.bicep' = {
  name: 'credprox-live-r2-whatif'
  scope: rg
  params: {
    mainLocation: mainLocation
    vaultLocation: vaultLocation
    officerPrincipalId: officerPrincipalId
    officerRoleId: officerRoleId
    vaultUserRoleDefinitionId: vaultUserRoleDefinitionId
    acrPullRoleId: acrPullRoleId
  }
}
