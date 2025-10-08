---
title: "Azure Key Vault"
---

# Azure Key Vault secret provider
Azure Key Vault secret provider brings secrets from Azure Key Vault to your application.

## Installation
Adding secrets from Azure Key Vault into the secret store requires following package:

```powershell
PM > Install-Package Arcus.Security.Providers.AzureKeyVault
```

## Configuration
After installing the package, the additional extensions becomes available when building the secret store.

```csharp
var builder = Host.CreateDefaultBuilder(args);
builder.ConfigureSecretStore((_, store) =>
{
    // #1 Using token credentials.
    store.AddAzureKeyVault("https://myvault.vault.azure.net", new ManagedIdentityCredential());

    // #2 Using already registered secret client.
    store.AddAzureKeyVault((IServiceProvider provider) =>
    {
        return provider.GetRequiredService<SecretClient>();
    })
});

builder.ConfigureServices(services =>
{
    services.AddAzureClients(clients =>
    {
        clients.AddSecretClient(new Uri("https://myvault.vault.azure.net"));
        clients.UseCredential(new ManagedIdentityCredential());
    })
});
```

## Additional functionality
The following functionality is only available on the Azure Key Vault secret provider. First, retrieve the specific secret provider instance from the secret store to interact with it directly.

```csharp
using Arcus.Security;

ISecretStore store = ...

var provider = store.GetProvider<KeyVaultSecretProvider>("MySecrets");
```

> 🔗 See the [secret store](../index.mdx) feature documentation for more information on naming secret providers during registration.

<details>
<summary><h3 style={{ margin:0 }}>🔢 Versioned secrets</h3></summary>

Azure Key Vault secrets can have multiple versions. Upon rotation, there are situations that the application should accept multiple versions of a single secret. The secret provider implementation provides a way to retrieve a subset of Azure Key Vault secrets, wrapped into a single `SecretsResult`, representing the success/failure state of the entire subset.

```csharp
using Arcus.Security;

KeyVaultSecretProvider provider = ...

SecretsResult result = await provider.GetVersionedSecretsAsync("<secret-name>", amountOfVersions: 2);
if (result.IsSuccess)
{
    // SecretsResult implements `IEnumerable<SecretResult>`
    SecretResults[] secrets = result.ToArray();
}
```

:::note
The `amountOfVersions` represents the number of most recent versions of the secret, starting from the currently enabled one.
:::

</details>

<details>
<summary><h3 style={{ margin:0 }}>💾 Storing secrets</h3></summary>

The secret provider implementation supports storing of secrets as well. 
```csharp
using Arcus.Security;

KeyVaultSecretProvider provider = ...

SecretResult result = await provider.SetSecretAsync("<secret-name>", "<secret-value>");
```
</details>