---
title: "Named secret providers"
layout: default
---

# Retrieve a specific secret provider from the secret store

The default workings of the secret store, is that a set of secret providers are registered and the consumer gets access to all of secrets provided by using `ISecretProvider`.

In some cases, you may want to retrieve a specific secret provider or a subset of secret providers from the store because that secret provider has some functionality that the other providers don't have.

In those cases, you can register your secret provider(s) with a name so that, in a later stage, you can retrieve back your named provider(s).

## Registering a named secret provider

Lets consider that you want explicitly use the built-in environment variables secret provider.
First, the secret provider has to be registered with a unique name. 

```csharp
.ConfigureSecretStore((config, stores) =>
{
    stores.AddEnvironmentVariables(..., name: "environment-variables");
})
```

## Retrieving a named secret provider

Now that the named environment variables secret provider is registered, we are able to retrieve this provider in our application.

Instead of injecting `ISecretProvider` in your application to access secrets, we'll inject `ISecretStore` interface to retrieve named secret providers.

```csharp
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Providers;

namespace Application
{
    [ApiController]
    public class OrderController : ControllerBase
    {
        public class OrderController(ISecretStore secretStore)
        {
             // Gets the `ISecretProvider` with the matched name (with either using the `ISecretProvider` as return type or your own generic type).
             // ⚠ The name of the registered secret providers should be unique when retrieving the concrete secret provider; 
             //         otherwise, an exception will be thrown when you try to access the `GetProvider<>` or `GetCachedProvider<>`.
             var secretprovider = secretStore.GetProvider<EnvironmentVariableSecretProvider>("environment-variables");

             // Gets the `ICachedSecretProvider` with the matched name (with either using the `ICachedSecretProvider` as return type or your own generic type).
             // Mark that this only works when the secret provider was regisered as a cached secret provider.
             ICachedSecretProvider cachedSecretProvider = secretStore.GetCachedProvider("your-cached-secret-provider");
        }
    }
}
```

## Retrieving a subset of named secret providers

At some times, you may want to retrieve a subset of secret providers. This is especially useful when you want to control the external secret providers based application-specific settings.

Let's consider this secret store setup:

```csharp
using Microsoft.Extensions.DependencyInjection;

public static class Program
{
    public static void Main(string[] args)
    {
        return CreateDefaultBuilder(args).Build().Run();
    }

    private static IHostBuilder CreateDefaultBuilder(string[] args)
    {
        return Host.CreateDefaultBuilder(args)
                   .ConfigureAppConfiguration(builder => builder.AddCommandLine(args))
                   .ConfigureSecretStore((config, stores) =>
                   {
                        stores.AddEnvironmentVariables();

                        stores.AddAzureKeyVaultWithManagedIdentity("https://admin.vault.azure.net");

                        stores.AddAzureKeyVaultWIthManagedIdentity("https://user.vault.azure.net");
                   });
    }
}
```

Imagine that you actually want some parts of the application to only have access to the Azure Key Vault `admin` plus the environment variables, and other parts only the Azure Key Vault `user` plus the environment variables.
This can be used for authorization restrictions, performance-wise to limit the external calls...

This problem can also be fixed by adding the same name to the required subset. Let's use "Admin Secrets" and "User Secrets" as our names:

```csharp
using Microsoft.Extensions.DependencyInjection;

public static class Program
{
    public static void Main(string[] args)
    {
        return CreateDefaultBuilder(args).Build().Run();
    }

    private static IHostBuilder CreateDefaultBuilder(string[] args)
    {
        return Host.CreateDefaultBuilder(args)
                   .ConfigureAppConfiguration(builder => builder.AddCommandLine(args))
                   .ConfigureSecretStore((config, stores) =>
                   {
                        stores.AddEnvironmentVariables(configureOptions: options => options.Name = "Admin Secrets")
                              .AddAzureKeyVaultWithManagedIdentity("https://admin.vault.azure.net", configureOptions: options => options.Name = "Admin Secrets");
                        
                        stores.AddEnvironmentVariables(configureOptions: options => options.Name = "User Secrets")
                              .AddAzureKeyVaultWIthManagedIdentity("https://user.vault.azure.net", configureOptions: options => options.Name = "User Secrets");
                   });
    }
}
```

Within the application, you can now use either subset of the secret store by calling the correct configured name:

```csharp
using Arcus.Security.Core;

namespace Application
{
    [ApiController]
    public class OrderController : ControllerBase
    {
        public class OrderController(ISecretStore secretStore)
        {
            // Combines the environment variables + Azure Key Vault 'admin'
            ISecretProvider adminSecretProvider = secretStore.GetProvider("Admin Secrets");

            // Combines the environment variables + Azure Key Vault 'user'
            ISecretProvider userSecretProvider = secretStore.GetProvider("User Secrets");
        }
    }
}
```