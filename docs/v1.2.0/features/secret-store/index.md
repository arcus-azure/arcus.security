---
title: "Secret store integration"
layout: default
---

# Using secret store
As alternative to the usage of placing secrets into an `IConfiguration` instance in your application, the `Arcus.Security.Core` package provides a alternative concept called 'secret store'.

We provide an approach similar to how `IConfiguration` is built, but with a focus on secrets. You can pick and choose the secret providers you want to use and we'll get the job done!

Once register, you can fetch all secrets by using `ISecretProvider` which will get secrets from all the different registered secret providers.

## Installation
For this feature, the following package needs to be installed:

```shell
PM > Install-Package Arcus.Security.Core
```

## Usage
The secret stores are configured during the initial application build-up in the `Program.cs`:

```csharp
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
                    builder.AddEnvironmentVariables();
#if DEBUG
                    builder.AddConfiguration(config);
#endif
                    var keyVaultName = config["KeyVault_Name"];
                    builder.AddEnvironmentVariables()
                            .AddAzureKeyVaultWithManagedServiceIdentity($"https://{keyVaultName}.vault.azure.net");
                })
                .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

Once the secret providers are defined, the `ISecretProvider` can be used as any other registered service:

```csharp
[ApiController]
public class HealthController : ControllerBase
{
    public HealthController(ISecretProvider secretProvider)
    {
    }
}
```

## Built-in secret providers
Several built in secret providers available in the package.

* [Environment variables](./../../features/secret-store/provider/environment-variables)
* [Configuration](./../../features/secret-store/provider/configuration)
* [Azure key vault](./../../features/secret-store/provider/key-vault)

If you require an additional secret providers that aren't available here, please [this document](./../../features/secret-store/create-new-secret-provider) that describes how you can create your own secret provider.

[&larr; back](/)
