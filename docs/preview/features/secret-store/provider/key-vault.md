---
title: "Azure Key Vault secret store"
layout: default
---

# Azure key vault secret provider
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
                       // Adding the Azure Key Vault secret source with the built-in overloads
                       builder.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri);

                      // Several other built-in overloads are available too:
                      // `AddAzureKeyVaultWithServicePrincipal`
                      // `AddAzureKeyVaultWithCertificate`

                      // Or, alternatively using the fully customizable approach.
                      var vaultAuthentication = new ManagedServiceIdentityAuthentication();
                      var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);

                      builder.AddAzureKeyVault(vaultAuthentication, vaultConfiguration);
                    })
                    .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

[&larr; back](/)
