---
title: "Create a new secret provider"
layout: default
---

# Create a new secret provider

## Prerequisites

The secret providers are configured during the initial application build-up in the `Program.cs`:

```csharp
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
                       builder.AddEnvironmentVariables();
                   })
                   .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

This section describes how a new secret store source can be added to the pipeline.

## Developing a secret provider

1. Install the NuGet package `Arcus.Security.Core`.
2. Implement your own implementation of the `ISecretProvider` 
   ex:
   ```csharp
   using Arcus.Security.Core;

   namespace Application.Security.CustomProviders
   {
       public class RegistrySecretProvider : ISecretProvider
       {
           public Task<string> GetRawSecretAsync(string secretName)
           {
               object value = Registry.LocalMachine.GetValue(secretName);
               return Task.FromResult(value?.ToString());
           }

           public async Task<Secret> GetSecretAsync(string secretName)
           {
               string secretValue = await GetRawSecretAsync(secretName);
               return new Secret(secretValue);
           }
       }
   }
   ```
3. Optionally, you can provide an extension for a consumer-friendly way to add the provider.
   ex:
   ```csharp
    namespace Microsoft.Extensions.Hosting
    {
        public static class SecretStoreBuilderExtensions
        {
            public static SecretStoreBuilder AddRegistry(this SecretStoreBuilder builder)
            {
                var provider = new RegistrySecretProvider();
                return builder.AddProvider(provider);
            }
        }
    }
   ``` 
   And in the `Startup.cs`:
   ```csharp
   .ConfigureSecretStore((context, config, builder) =>
   {
       builder.AddRegistry();
   })
   ```

   Or, you can use your provider directly.
   ```csharp
   .ConfigureSecretStore((context, config, builder) => 
   {
       var provider = new RegistrySecretProvider();
       builder.AddProvider(provider);
   })
   ```
4. Now, the secret source is available in the resulting `ISecretProvider` registered in the dependency injection container.
   ex:
   ```csharp
   using Arcus.Security.Core;

   namespace Application.Controllers
   {
       [ApiController]
       public class OrderController : ControllerBase
       {
           public class OrderController(ISecretProvider secretProvider)
           {
           }
       }
   }
   ```

5. Note that when your secret provider requires caching, you can wrap the provider in a `CachedSecretProvider` at registration:
   ex:
   ```csharp
    using Arcus.Security.Core.Caching;

    namespace Microsoft.Extensions.Hosting
    {
        public static class SecretStoreBuilderExtensions
        {
            public static SecretStoreBuilder AddCachedRegistry(this SecretStoreBuilder builder)
            {
                var provider = new RegistrySecretProvider();
                var configuration = new CacheConfiguration(TimeSpan.FromSeconds(5));

                return builder.AddProvider(new CachedSecretProvider(provider, configuration));
            }
        }
    }
   ```

   When accessing the provider in the application, you can use the `ICachedSecretProvider` to have access to the cache-specific methods.
   ex:
   ```csharp
   using Arcus.Security.Core.Caching;

    namespace Application.Controllers
    {
        [ApiController]
        public class OrderController : ControllerBase
        {
            public class OrderController(ICachedSecretProvider secretProvider)
            {
            }
        }
    }
   ```

## Contribute your secret provider

We are open for contributions and are more than happy to receive pull requests with new secret providers!
[&larr; back](/)
