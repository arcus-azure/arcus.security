---
title: "Secret store integration"
layout: default
slug: /features/secret-store
sidebar_position: 1
---

# Using secret store
As alternative to the usage of placing secrets into an `IConfiguration` instance in your application, the `Arcus.Security.Core` package provides a alternative concept called 'secret store'.

We provide an approach similar to how `IConfiguration` is built, but with a focus on secrets. You can pick and choose the secret providers you want to use and we'll get the job done!

Once register, you can fetch all secrets by using `ISecretProvider` which will get secrets from all the different registered secret providers.

> :bulb: See [this section](#using-secret-store-within-azure-functions) if you want to use the secret store functionality whitin Azure Functions.

## Built-in secret providers
Several built in secret providers available in the package.

* [Environment variables](features/secret-store/provider/environment-variables)
* [Configuration](features/secret-store/provider/configuration)
* [Azure key vault](features/secret-store/provider/key-vault)
* [User Secrets](features/secret-store/provider/user-secrets)

If you require an additional secret providers that aren't available here, please [this document](features/secret-store/create-new-secret-provider) that describes how you can create your own secret provider.

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

## Using secret store within Azure Functions

### Installation
For this feature, the following package needs to be installed:

```shell
PM > Install-Package Arcus.Security.AzureFunctions
```

### Usage
The secret stores are configured during the initial application build-up in the `Startup.cs`:

```csharp
using Microsoft.Azure.Functions.Extensions.DependencyInjection;

[assembly: FunctionsStartup(typeof(Startup))]

namespace MyHttpAzureFunction
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            builder.ConfigureSecretStore(stores =>
            {
                stores.AddEnvironmentVariables();

                var keyVaultName = config["KeyVault_Name"];
                stores.AddEnvironmentVariables()
                      .AddAzureKeyVaultWithManagedServiceIdentity($"https://{keyVaultName}.vault.azure.net");
            })
        }
    }
}
```

Once the secret providers are defined, the `ISecretProvider` can be used as any other registered service:

```csharp
using Arcus.Security.Core;

namespace Application
{
    public class MyHttpTrigger
    {
        public MyHttpTrigger(ISecretProvider secretProvider)
        {
        }

        [FunctionName("MyHttpTrigger")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            return new OkObjectResult("Response from function with injected dependencies.");
        }
    }
}
```

