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
using Arcus.Security.Core.Caching.Configuration;
using Microsoft.Extensions.Hosting;

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
                         // `keyVaultUri`: the URI where the Azure Key Vault is located.
                         builder.AddAzureKeyVaultWithManagedIdentity(keyVaultUri);

                        // Several other built-in overloads are available too:
                        // `AddAzureKeyVaultWithServicePrincipal`
                        // `AddAzureKeyVaultWithCertificate`

                        // Or, alternatively using the fully customizable approach.
                        // `clientId`: The client id to authenticate for a user assigned managed identity.
                        // More information on user assigned managed identities can be found here: https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#how-a-user-assigned-managed-identity-works-with-an-azure-vm</param>
                        var vaultAuthentication = new ChainedTokenCredential(new ManagedIdentityCredential(clientId), new EnvironmentCredential());
                        var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);

                        builder.AddAzureKeyVault(vaultAuthentication, vaultConfiguration);

                        // Adding a default cached variant of the Azure Key Vault provider (default: 5 min caching).
                        builder.AddAzureKeyVaultWithManagedIdentity(keyVaultUri, cacheConfiguration: CacheConfiguration.Default);

                        // Assing a configurable cached variant of the Azure Key Vault provider.
                        var cacheConfiguration = new CacheConfiguration(TimeSpan.FromMinutes(1));
                        builder.AddAzureKeyVaultWithManagedIdentity(keyVaultUri, cacheConfiguration);

                        // Tracking the Azure Key Vault dependency which works well together with Application Insights (default: `false`).
                        // See https://observability.arcus-azure.net/features/writing-different-telemetry-types#measuring-custom-dependencies for more information.
                        builder.AddAzureKeyVaultWithManagedIdentity(keyVaultUri, configureOptions: options => options.TrackDependency = true);

                        // Adding the Azure Key Vault secret provider, using `-` instead of `:` when looking up secrets.
                        // Example - When looking up `ServicePrincipal:ClientKey` it will be changed to `ServicePrincipal-ClientKey`.
                        builder.AddAzureKeyVaultWithManagedIdentity(keyVaultUri, mutateSecretName: secretName => secretName.Replace(":", "-"));

                        // Providing an unique name to this secret provider so it can be looked up later.
                       // See: "Retrieve a specific secret provider from the secret store"
                       builder.AddAzureKeyVaultWithManagedIdentity(..., name: "AzureKeyVault.ManagedIdentity");
                    })
                    .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

[&larr; back](/)
