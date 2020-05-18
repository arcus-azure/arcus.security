---
title: "Create a new secret source"
layout: default
---

# Create a new secret source

## Prerequisits

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
                .ConfigureSecretStore((context, config, builder) =>
                {
                    builder.AddEnvironmentVariables();
                })
                .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

This section describes how a new secret store source can be added to the pipeline.

## Developing a secret source

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
3. Optionally, you can provide an extension for a consumer-friendly way to add the provider as source.
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

[&larr; back](/)