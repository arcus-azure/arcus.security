---
title: "Azure Functions support"
layout: default
---

# Using secret store within Azure Functions
This separate documentation section explains how the Arcus secret store can be used within Azure Functions environments (both in-process and isolated). 

## Using secret store within in-process Azure Functions
To more easily configure the secret store, we provided a dedicated package that builds on top of the `IFunctionsHostBuilder`:

## Installation
For this feature, the following package needs to be installed:

```shell
PM > Install-Package Arcus.Security.AzureFunctions
```

### Usage
The secret stores are configured during the initial application build-up in the `Startup.cs`:
```csharp
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

[assembly: FunctionsStartup(typeof(Startup))]

namespace MyHttpAzureFunction
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            builder.ConfigureSecretStore((FunctionsHostBuilderContext context, IConfiguration config, SecretStoreBuilder stores) =>
            {
                var keyVaultName = config["KeyVault_Name"];
                stores.AddEnvironmentVariables()
                      .AddAzureKeyVaultWithManagedIdentity($"https://{keyVaultName}.vault.azure.net");
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

## Using secret store within isolated Azure Functions
Since isolated Azure Functions are built with the default `HostBuilder`, the general secret store packages can be used in this environment. No need to install the dedicated `Arcus.Security.AzureFunctions` package.

### Usage
Using the available extensions on the `HostBuilder` or `IServiceCollection`, the secret store can be added, just like a Web API or console application.

```csharp
var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults(builder =>
    {
        
    })
   .ConfigureSecretStore((context, config, stores) =>
   {
        builder.AddEnvironmentVariables()
               .AddAzureKeyVaultWithManagedIdentity($"https://{keyVaultName}.vault.azure.net");
   })
    .Build();
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

        [Function("MyHttpTrigger")]
        public HttpResponseData Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequestData req,
            ILogger log)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            return response;
        }
    }
}
```