---
title: "Azure Functions secret store integration"
layout: default
---

# Using secret store within Azure Functions

As alternative to the usage of placing secrets into an `IConfiguration` instance in your application, the `Arcus.Security.AzureFunctions` package provides a alternative concept called 'secret store'.

We provide an approach similar to how `IConfiguration` is built, but with a focus on secrets. You can pick and choose the secret providers you want to use and we'll get the job done!

Once register, you can fetch all secrets by using `ISecretProvider` which will get secrets from all the different registered secret providers.

## Installation
For this feature, the following package needs to be installed:

```shell
PM > Install-Package Arcus.Security.AzureFunctions
```

## Usage
The secret stores are configured during the initial application build-up in the `Startup.cs`:

```csharp
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

## Built-in secret providers
Several built in secret providers available in the package.

* [Environment variables](./../../features/secret-store/provider/environment-variables)
* [Configuration](./../../features/secret-store/provider/configuration)
* [Azure key vault](./../../features/secret-store/provider/key-vault)

If you require an additional secret providers that aren't available here, please [this document](./../../features/secret-store/create-new-secret-provider) that describes how you can create your own secret provider.

[&larr; back](/)