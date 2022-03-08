---
title: "Consuming Azure Key Vault secrets"
layout: default
---

# Consuming Azure Key Vault secrets

## Store Azure Key vault secrets
The [Azure Key vault secret provider](../secret-store/provider/key-vault.md) provides the capability to also store secrets. This functionality is only available on the secret provider itself and not on the entire secret store.

Following steps guide you to store an Azure Key Vault secret via the Azure Key vault secret provider.
1. Register the Azure Key Vault secret provider as a [named secret provider](../secret-store/named-secret-providers.md).
    ```csharp
    stores.AddAzureKeyVaultWithManagedIdentity(..., name: "AzureKeyVault.ManagedIdentity");
    ```
2. Retrieve the Azure Key Vault secret provider from the `ISecretStore` (see the [named secret provider docs](../secret-store/named-secret-providers.md) for info)
   ```csharp
   ISecretStore secretStore = ...
   var secretProvider = secretStore.GetProvider<KeyVaultSecretProvider>("AzureKeyVault.ManagedIdentity);
   ```
3. Store the secret by calling the `StoreSecretAsync` method.
   ```csharp
   KeyVaultSecretProvider secretProvider = ...
   await secretProvider.StoreSecretAsync("MySecret", "P@ssw0rd!);
   ```

## Open for extension
You can easily extend the Key Vault provider by overriding the `GetSecret*Async` methods on the it.

This useful to provide additional logging, for example, during the retrieval of the secrets.

```csharp
using Microsoft.Extensions.Logging;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault;

public class LoggedKeyVaultSecretProvider : KeyVaultSecretProvider
{
    private readonly ILogger _logger;

    public LoggedKeyVaultSecretProvider(ILogger<LoggedKeyVaultSecretProvider> logger)
    {
        _logger = logger;
    }

    public override async Task<Secret> GetSecretAsync(string secretName)
    {
        using (var measurement = DependencyMeasurement.Start())
        {
            Secret secret = await base.GetSecretAsync(secretName);
            _logger.LogDependency("Azure Key Vault", "Secret", isSuccessful: true, startTime: measurement.StartTime, duration: measurement.Elapsed);
        }

        return secret;
    }
}
```

