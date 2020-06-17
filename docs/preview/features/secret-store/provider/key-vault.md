---
title: "Azure Key Vault secret provider"
layout: default
---

# Azure Key Vault secret provider
Azure Key Vault secret provider brings secrets from Azure Key Vault to your application.

## Installation
Adding secrets from Azure Key Vault into the secret store requires following package:

```shell
PM > Install-Package Arcus.Security.Providers.AzureKeyVault
```

## Configuration
After installing the package, the addtional extensions becomes available when building the secret store.

```csharp
public class Program
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args)
    {    
        return Host.CreateDefaultBuilder(args)
                   .ConfigureSecretStore((context, config, builder) =>
                   {
                         // Adding the Azure Key Vault secret provider with the built-in overloads
                         builder.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri);

                        // Several other built-in overloads are available too:
                        // `AddAzureKeyVaultWithServicePrincipal`
                        // `AddAzureKeyVaultWithCertificate`

                        // Or, alternatively using the fully customizable approach.
                        var vaultAuthentication = new ManagedServiceIdentityAuthentication();
                        var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);

                        builder.AddAzureKeyVault(vaultAuthentication, vaultConfiguration);

                        // Adding a default cached variant of the Azure Key Vault provider (default: 5 min caching).
                        builder.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, allowCaching: true);

                        // Assing a configurable cached variant of the Azure Key Vault provider.
                        var cacheConfiguration = new CacheConfiguration(TimeSpan.FromMinutes(1));
                        builder.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, cacheConfiguration);
                    })
                    .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

[&larr; back](/)
