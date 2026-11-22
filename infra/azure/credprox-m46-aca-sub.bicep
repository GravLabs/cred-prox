// Subscription-scoped wrapper for the M46 ACA template. Its only purpose is the
// OFFLINE gate: `az deployment sub what-if` validates the whole resource set
// without an existing resource group (a group-scoped what-if would first need
// the RG - a mutation we may not perform offline). Not used for the live apply,
// which deploys credprox-m46-aca.bicep group-scoped from scripts/live-m46-aca.sh.
// The what-if itself is a lead-run step (see docs/live-testing.md).
targetScope = 'subscription'
param rgName string = 'credprox-m46-aca'
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
module aca 'credprox-m46-aca.bicep' = {
  name: 'credprox-m46-aca-whatif'
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
