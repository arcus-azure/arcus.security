---
title: "Create a new secret provider"
layout: default
---

# Create a new secret provider

- [Prerequisites](#prerequisites)
- [Developing a secret provider](#developing-a-secret-provider)
- [Adding caching to your secret provider](#adding-caching-to-your-secret-provider)
- [Adding secret name mutation before looking up secret](#adding-secret-name-mutation-before-looking-up-secret)
- [Adding critical exceptions](#add-critical-exceptions)
- [Contribute your secret provider](#contribute-your-secret-provider)

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

### Adding secret name mutation before looking up secret

When you want secret names 'changed' or 'mutated' before they go through your secret provider (ex. changing `Arcus.Secret` to `ARCUS_SECRET`);
you can pass allong a custom mutation function during the registration:

```csharp
namespace Microsoft.Extensions.Hosting
{
    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddRegistry(this SecretStoreBuilder builder)
        {
            var provider = RegistrySecretProvider();

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
            var provider = RegistrySecretProvider();

            return builder.AddProvider(secretprovider, mutateSecretName);
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
and that this critical exception is eventually throwed by the secret store when you're looking up secrets.

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
        public static SecretStoreBuilder AddHttpVault(this SecretStoreBuilder builder)
        {
            // Make sure that ALL exceptions of this type is considered critical.
            builder.AddCriticalException<AuthenticationException>();

            // Make sure that only exceptions of this type where the given filter succeeds is considered critical.
            builder.AddCriticalException<HttpOperationException>(exception => 
            {
                return exception.Response.HttpStatusCode == HttpStatusCode.Forbidden;
            });

            return builder.AddProvider(new RegistrySecretProvider());
        }
    }
}
```

> Note that when multiple secret providers in the secret store are throwing critical exceptions upon retrieving a secret, then these critical exceptions will be wrapped inside a `AggregateException`.
> In the other case the single critical exception is being throwed.

## Contribute your secret provider

We are open for contributions and are more than happy to receive pull requests with new secret providers!
