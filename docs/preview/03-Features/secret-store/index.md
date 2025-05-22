---
title: "What is it?"
layout: default
slug: /features/secret-store
sidebar_position: 1
---

# Using secret store
As alternative to the usage of placing secrets into an `IConfiguration` instance in your application, the `Arcus.Security.Core` package provides a alternative concept called 'secret store'.

We provide an approach similar to how `IConfiguration` is built, but with a focus on secrets. You can pick and choose the secret providers you want to use and we'll get the job done!

Once register, you can fetch all secrets by using `ISecretProvider` which will get secrets from all the different registered secret providers.

> :bulb: See [this section](./azure-functions.md) if you want to use the secret store functionality within Azure Functions.

![Arcus secret store integration example](/img/arcus-secret-store-diagram.png)

## Why would I use it?
Why would you use our Arcus secret store instead of just using the Azure SDK directly to access Azure Key Vault secrets?

The Arcus secret store has some advantages over using the Azure SDK or configuration directly:

**✔ Caching**
* We provide caching so the secret providers will not be called upon every secret retrieval. This helps you avoiding hitting service limitations and we provide [asynchronous cache invalidation](https://background-jobs.arcus-azure.net/features/security/auto-invalidate-secrets).

**✔ Plug & play**
* We support using multiple and combinations of secret providers so with a single secret retrieval can query multiple secret providers (also multiple Azure Key Vaults).

**✔ Design for security** 
* While using configuration for storing secrets can be good for development it is not a safe approach. With the secret store, we provide a single place to retrieve secrets instead of scattering the integration across the application. 
* Separating configuration data and sensitive secrets is key in developing secure projects. Vulnerabilities gets introduced when secrets are seen as data and are included in logs, for example. Or when expired secrets doesn't get transient handling upon retrieval.

**✔ Extensibility**
* Arcus secret store is highly extensible and can be extended with [your own custom secret providers](./create-new-secret-provider.md), [in-memory secret providers for testing](https://github.com/arcus-azure/arcus.testing/blob/master/docs/v0.3/features/inmemory-secret-provider.md)...

## Built-in secret providers
Several built in secret providers available in the package.

* [Configuration](./provider/configuration.md)
* [Environment variables](./provider/environment-variables.md)

And several additional providers in separate packages.

* [Azure Key Vault](./provider/key-vault.md)
* [Command line](./provider/cmd-line.md)
* [Docker secrets](./provider/docker-secrets.md)
* [HashiCorp](./provider/hashicorp-vault.md)
* [User Secrets](./provider/user-secrets.md)

If you require an additional secret providers that aren't available here, please [this document](./create-new-secret-provider.md) that describes how you can create your own secret provider.

## Additional features
Lists all the additional functions of the secret store.

* [Create a custom secret provider](./create-new-secret-provider.md)
* [Retrieve a specific secret provider](./named-secret-providers.md)

## Installation
For this feature, the following package needs to be installed:

```shell
PM > Install-Package Arcus.Security.Core
```

## Usage
The secret stores are configured during the initial application build-up in the `Program.cs`:

```csharp
using Microsoft.Extensions.Hosting;

public class Program
{
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((context, config) => 
                {
                    config.AddJsonFile("appsettings.json")
                          .AddJsonFile("appsettings.Development.json");
                })
                .ConfigureSecretStore((context, config, builder) =>
                {
#if DEBUG
                    builder.AddConfiguration(config);
#endif
                    var keyVaultName = config["KeyVault_Name"];
                    builder.AddEnvironmentVariables()
                           .AddAzureKeyVaultWithManagedIdentity($"https://{keyVaultName}.vault.azure.net");
                })
                .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

Once the secret providers are defined, the `ISecretProvider` can be used as any other registered service:

```csharp
using Arcus.Security.Core;

namespace Application.Controllers
{
    [ApiController]
    public class HealthController : ControllerBase
    {
        public HealthController(ISecretProvider secretProvider)
        {
        }
    }
}
```

### Configuring secret store without .NET host builder
The secret store is also available directly on the `IServiceCollection` for applications that run without a .NET hosting context but still want to make use of the Arcus secret store.

Just like you would register the secret store on the `HostBuilder`, you can use the `.AddSecretStore` extension method to register the secret store:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    IConfiguration configuration = 
        new ConfigurationBuilder()
            .AddEnvironmentVariables()
            .Build();

    services.AddSecretStore(stores =>
    {
        stores.AddEnvironmentVariables();
        
        #if DEBUG
        stores.AddConfiguration(configuration);
        #endif
    
        var keyVaultName = configuration["KeyVault_Name"];
        stores.AddAzureKeyVaultWithManagedServiceIdentity($"https://{keyVaultName}.vault.azure.net");
    });
}
```

When your application wants to access a secret, all it has to do is use `ISecretProvider` which will give you access to all the registered secret providers.

