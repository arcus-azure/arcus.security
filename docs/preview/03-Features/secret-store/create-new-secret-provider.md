---
title: "Create custom secret provider"
layout: default
---

# Create a new secret provider
The Arcus secret store allows custom secret provider implementations if you want to retrieve secrets from a location that is not built-in.
This section describes how you develop, configure and finally register your custom secret provider implementation into the Arcus secret store.

## Prerequisites
The secret providers are configured during the initial application build-up:

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
   ```csharp
   using Arcus.Security.Core;
   using Microsoft.Win32;

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

### Adding dependency services to your secret provider
When your secret provider requires additional services, configured in the dependency container, you can choose to pick an method overload that provides access to the `IServiceProvider`:

The example below shows how an `ILogger` instance is passed to the secret provider.
```csharp
using System;
using Microsoft.Extensions.Logging;

namespace Microsoft.Extensions.Hosting
{
    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddRegistry(this SecretStoreBuilder builder)
        {
            return builder.AddProvider((IServiceProvider serviceProvider) =>
            {
                var logger = serviceProvider.GetRequiredService<ILogger<RegistrySecretProvider>>();
                return new RegistrySecretProvider(logger);
            });
        }
    }
}
```

### Adding caching to your secret provider
When your secret provider requires caching, you can wrap the provider in a `CachedSecretProvider` at registration:
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

### Adding secret versions to your secret provider
When your secret storage location supports secret versions, you could consider adapting your secret provider to support these secret versions.
For more information on how you can use many secret versions in your application, see [this dedicated page](./versioned-secret-provider.md).

Implement from `IVersionedSecretProvider` instead of `ISecretProvider` to allow the secret store to pick that your secret provider supports secret versions.
The following example shows how the registry secret provider only supports two versions of a secret:
```csharp
using Arcus.Security.Core;
using Microsoft.Win32;

public class RegistrySecretProvider : IVersionedSecretProvider
{
    // Also implement the general `ISecretProvider` methods...

     public Task<IEnumerable<string>> GetRawSecretsAsync(string secretName, int amountOfVersions)
     {
         if (amountOfVersions >= 2)
         {
             object valueV1 = Registry.LocalMachine.GetValue("v1\\" + secretName);
             object valueV2 = Registry.LocalMachine.GetValue("v2\\" + secretName);

             return Task.FromResult(new[] { valueV1, valueV2 });
         }

         object valueV1 = Registry.LocalMachine.GetValue("v1\\" + secretName);
         return Task.FromResult(new[] { valueV1 });
     }

     public async Task<IEnumerable<Secret>> GetSecretAsync(string secretName, int amountOfVersions)
     {
         string secretValue = await GetRawSecretAsync(secretName);
         return new Secret(secretValue);
     }
}
```

The `amountOfVersions` can be configured via the secret provider options (`.AddVersionedSecret`).
Each secret provider registration has the ability to register a amount of secret versions for secret name, that amount is passed to your implementation. For more information, see [this dedicated page](./versioned-secret-provider.md).

> 💡 Note that versioned secrets can be combined with caching. The set of secrets will be cached, just like a single secret.

### Adding secret name mutation before looking up secret
When you want secret names 'changed' or 'mutated' before they go through your secret provider (ex. changing `Arcus.Secret` to `ARCUS_SECRET`);
you can pass along a custom mutation function during the registration:

```csharp
namespace Microsoft.Extensions.Hosting
{
    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddRegistry(this SecretStoreBuilder builder)
        {
            var secretProvider = new RegistrySecretProvider();

            return builder.AddProvider(secretProvider, options => options.MutateSecretName = secretName => secretName.Replace(".", "_").ToUpper());
        }
    }
}
```

Or allow users to specify this:

```csharp
namespace Microsoft.Extensions.Hosting
{
    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddRegistry(
        this SecretStoreBuilder builder, 
        Func<string, string> mutateSecretName = null)
        {
            var secretProvider = new RegistrySecretProvider();

            return builder.AddProvider(secretProvider, mutateSecretName);
        }
    }
}
```

So they can provide a custom mutation:

```csharp
.ConfigureSecretStore((config, stores) =>
{
    stores.AddRegistry(secretName => secretName.Replace(".", "_").ToUpper());
})
```

### Adding critical exceptions
When implementing your own `ISecretProvider`, you may come across situations where you want to throw an critical exception (for example: authentication, authorization failures...)
and that this critical exception is eventually thrown by the secret store when you're looking up secrets.

When the authentication (for example) only happens when your secret provider _actually_ looks for secrets, then you may want to benefit from this feature.
If you don't provide any critical exceptions yourself, the exception may only be logged and you may end up with only a `SecretNotFoundException`.

Adding these critical exception can be done during the registration of your secret provider:

```csharp
using System.Net;
using System.Security.Authentication;
using Microsoft.Rest;

namespace Microsoft.Extensions.Hosting
{
    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddHttpVault(this SecretStoreBuilder builder, string endpoint)
        {
            // Make sure that ALL exceptions of this type is considered critical.
            builder.AddCriticalException<AuthenticationException>();

            // Make sure that only exceptions of this type where the given filter succeeds is considered critical.
            builder.AddCriticalException<HttpOperationException>(exception => 
            {
                return exception.Response.HttpStatusCode == HttpStatusCode.Forbidden;
            });

            return builder.AddProvider(new HttpVaultSecretProvider(endpoint));
        }
    }
}
```

> Note that when multiple secret providers in the secret store are throwing critical exceptions upon retrieving a secret, then these critical exceptions will be wrapped inside a `AggregateException`.
> In the other case the single critical exception is being thrown.

## Contribute your secret provider
We are open for contributions and are more than happy to receive pull requests with new secret providers!