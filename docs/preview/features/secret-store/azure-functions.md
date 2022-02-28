---
title: "Using secret store within Azure Functions"
layout: default
---

# Using secret store within Azure Functions

## Installation
For this feature, the following package needs to be installed:

```shell
PM > Install-Package Arcus.Security.AzureFunctions
```

## Usage
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
