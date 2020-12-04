---
title: "Secret store integration"
layout: default
---

# Using secret store
As alternative to the usage of placing secrets into an `IConfiguration` instance in your application, the `Arcus.Security.Core` package provides a alternative concept called 'secret store'.

We provide an approach similar to how `IConfiguration` is built, but with a focus on secrets. You can pick and choose the secret providers you want to use and we'll get the job done!

Once register, you can fetch all secrets by using `ISecretProvider` which will get secrets from all the different registered secret providers.

> :bulb: See [this section](#using-secret-store-within-azure-functions) if you want to use the secret store functionality whitin Azure Functions.

## Built-in secret providers
Several built in secret providers available in the package.

* [Configuration](./../../features/secret-store/provider/configuration)
* [Environment variables](./../../features/secret-store/provider/environment-variables)

And several additional providers in seperate packages.

* [Azure Key Vault](./../../features/secret-store/provider/key-vault)
* [HashiCorp](./../../features/secret-store//provider/hashicorp-vault)
* [User Secrets](./../../features/secret-store/provider/user-secrets)

If you require an additional secret providers that aren't available here, please [this document](./../../features/secret-store/create-new-secret-provider) that describes how you can create your own secret provider.

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
                    builder.AddAzureKeyVaultWithManagedServiceIdentity($"https://{keyVaultName}.vault.azure.net");
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

### Using secret store outside .NET hosting
The secret store is also available directly on the `IServiceCollection` for applications that run without a .NET hosting context but still want to make use of the Arcus secret store.

Just like you would register the secret store on the `HostBuilder`, you can use the `.AddSecretStore` extension to register the secret store:

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
        builder.AddConfiguration(configuration);
        #endif
    
        var keyVaultName = configuration["KeyVault_Name"];
        stores.AddAzureKeyVaultWithManagedServiceIdentity($"https://{keyVaultName}.vault.azure.net");
    });
}
```

When the dependency injection container injects the dependent services in the rest of your application, 
the secret store will provide with you an `ISecretProvider` instance that contains the registered secret providers.

## Using secret store within Azure Functions

### Installation
For this feature, the following package needs to be installed:

```shell
PM > Install-Package Arcus.Security.AzureFunctions
```

### Usage
The secret stores are configured during the initial application build-up in the `Startup.cs`:

```csharp
[assembly: FunctionsStartup(typeof(Startup))]

namespace MyHttpAzureFunction
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            builder.ConfigureSecretStore(stores =>
            {
                builder.AddEnvironmentVariables();

                var keyVaultName = config["KeyVault_Name"];
                builder.AddEnvironmentVariables()
                       .AddAzureKeyVaultWithManagedServiceIdentity($"https://{keyVaultName}.vault.azure.net");
            })
        }
    }
}
```

Once the secret providers are defined, the `ISecretProvider` can be used as any other registered service:

```csharp
public class MyHttpTrigger
{
    public MyHttpTrigger(ISecretProvide secretProvider)
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
```

## Secret store configuration
The secret store as additional configuration that controls the behavior of the store.
See below the available features so you can setup your secret store for your needs.

### Include security auditing
The secret store has the ability to audit each secret retrieval so malicious activity can be spotted more easily.
This functionality is available in both the regular .NET Core as Azure Functions environment.

```csharp
.ConfigureSecretStore((config, stores) =>
{
    // Will log an security event for each retrieved secret, including the secret name and the provider that has tried to retrieve the secret.
    // Default: `false`
    stores.WithAuditing(options => options.EmitSecurityEvents = true);
})
```

[&larr; back](/)
