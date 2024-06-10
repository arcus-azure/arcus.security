param (
  [string] $resourceGroupName,
  [string] $keyVaultName,
  [string] $secretName
)

Describe "key vault" {
  Context "availability" {
    It "should contain a single vault with name" {
      $vaults = Get-AzKeyVault -ResourceGroupName $resourceGroupName
      $vaults.Count | Should -Be 1
      $vaults[0].Name | Should -Be $keyVaultName
    }
    It "should contain a secret with name" {
      $secrets =$actualSecret | Should -Be $secretName
      $secrets.Name | Should -Contain $secretName 
    }
  }
}