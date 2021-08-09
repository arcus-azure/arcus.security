---
title: "Consuming Azure Key Vault secrets"
layout: default
---

# Consuming Azure Key Vault secrets
You can easily create a Key Vault secret provider - The only thing you need to do is specify how you want to configure and to what vault.

```csharp
var vaultAuthentication = new ManagedServiceIdentityAuthentication();
var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
var keyVaultSecretProvider = new KeyVaultSecretProvider(vaultAuthentication, vaultConfiguration)
```

You can find a list of supported authentication schemes for Azure Key Vault [here](features/auth/azure-key-vault).

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

