$resourceGroupName = $env:RESOURCEGROUP_NAME
$keyVaultName = $env:KEYVAULT_NAME
$secretName = $env:SECRET_NAME
$secretValue = $env:SECRET_VALUT

Describe "key vault" {
  BeforeAll {
    $vault = Get-AzKeyVault -ResourceGroupName $resourceGroupName -VaultName $keyVaultName
  }
  Context "availability" {
    It "should contain only a single vault with name" {
      $vaults = Get-AzKeyVault -ResourceGroupName $resourceGroupName
      $vaults.Count | Should -Be 1
      $vaults[0].Name | Should -Be $keyVaultName
    }
    It "should contain an enabled secret with name" {
      $actualSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName
      $actualSecret.Enabled | Should -Be $true -Message "should be marked 'enabled'"
      $actualSecretValue = ConvertFrom-SecureString -SecureString $actualSecret.SecretValue
      $actualSecretValue | Should -Be $secretValue
    }
  }
  Context "configuration" {
    It "should use SKU Standard" {
      $vault.Sku | Should -Be "Standard"
    }
  }
  Context "security" {
    BeforeAll {
      $roleAssignments = Get-AzRoleAssignment -Scope $vault.ResourceId
    }
    It "should not have admin role permissions" {
      $roleAssignments.Name | Should -Not -Contain 'Key Vault Administrator'
    }
    It "should not contain key role permissions" {
      $roleAssignments.Name | Should -Not -Match 'Key Vault Keys'
    }
    It "Should not contain crypto role permissions" {
      $roleAssignments.Name | Should -Not -Match 'Key Vault Crypto'
    }
  }
}