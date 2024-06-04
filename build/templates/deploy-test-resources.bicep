// Define the location for the deployment of the components.
param location string

// Define the name of the resource group where the components will be deployed.
param resourceGroupName string

// Define the name of the Key vault.
param keyVaultName string

// Define the name of the secret that will be added to the Key vault.
param secretName string

// Define the secret value that will be by default added to the Key vault.
@secure()
param secretValue string

// Define the Service Principal ID that needs access full access to the deployed resource group.
param servicePrincipal_objectId string

targetScope='subscription'

module resourceGroup 'br/public:avm/res/resources/resource-group:0.2.3' = {
  name: 'resourceGroupDeployment'
  params: {
    name: resourceGroupName
    location: location
  }
}

resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' existing = {
  name: resourceGroupName
}

module vault 'br/public:avm/res/key-vault/vault:0.6.1' = {
  name: 'vaultDeployment'
  dependsOn: [
    resourceGroup
  ]
  scope: rg
  params: {
    name: keyVaultName
    location: location
    roleAssignments: [
      {
        principalId: servicePrincipal_objectId
        roleDefinitionIdOrName: 'Key Vault Secrets officer'
      }
    ]
    secrets: [
      {
        name: secretName
        value: secretValue
      }
    ]
  }
}

output Arcus_TenantId string = subscription().tenantId
output Arcus_KeyVault_Uri string = vault.outputs.uri
output Arcus_KeyVault_TestKeyName string = secretName
