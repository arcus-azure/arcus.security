---
title: "Create a new secret provider"
layout: default
---

# Create a new secret provider

- [Prerequisites](#prerequisites)
- [Developing a secret provider](#developing-a-secret-provider)
- [Adding caching to your secret provider](#adding-caching-to-your-secret-provider)
- [Adding secret name mutation before looking up secret](#adding-secret-name-mutation-before-looking-up-secret)
- [Contribute your secret provider](#contribute-your-secret-provider)

## Prerequisites

The secret providers are configured during the initial application build-up in the `Program.cs`:

```csharp
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
   ```
3. Optionally, you can provide an extension for a consumer-friendly way to add the provider.
   ex:
   ```csharp
    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddRegistry(this SecretStoreBuilder builder)
        {
            var provider = new RegistrySecretProvider();
            return builder.AddProvider(provider);
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
   [ApiController]
   public class OrderController : ControllerBase
   {
       public class OrderController(ISecretProvider secretProvider)
       {
       }
   }
   ```

### Adding caching to your secret provider

When your secret provider requires caching, you can wrap the provider in a `CachedSecretProvider` at registration:

```csharp
public static class SecretStoreBuilderExtensions
{
    public static SecretStoreBuilder AddCachedRegistry(this SecretStoreBuilder builder)
    {
        var provider = new RegistrySecretProvider();
        var configuration = new CacheConfiguration(TimeSpan.FromSeconds(5));
        
        return builder.AddProvider(new CachedSecretProvider(provider, configuration));
    }
}
```

When accessing the provider in the application, you can use the `ICachedSecretProvider` to have access to the cache-specific methods.
ex:
```csharp
[ApiController]
public class OrderController : ControllerBase
{
    public class OrderController(ICachedSecretProvider secretProvider)
    {
    }
}
```

### Adding secret name mutation before looking up secret

When you want secret names 'changed' or 'mutated' before they go through your secret provider (ex. changing `Arcus.Secret` to `ARCUS_SECRET`);
you can pass allong a custom mutation function during the registration:

```csharp
public static class SecretBuilderExtensions
{
    public static SecretStoreBuilder AddRegistry(this SecretStoreBuilder builder)
    {
        var provider = RegistrySecretProvider();
        
        return builder.AddProvider(secretProvider, secretName => secretName.Replace(".", "_").ToUpper());
    }
}
```

## Contribute your secret provider

We are open for contributions and are more than happy to receive pull requests with new secret providers!
[&larr; back](/)
