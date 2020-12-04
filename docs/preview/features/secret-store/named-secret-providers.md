---
title: "Named secret providers"
layout: default
---

# Retrieve a specific secret provider from the secret store

The default workings of the secret store, is that a set of secret providers are registered and the consumer gets access to all of secrets provided by using `ISecretProvider`.

In some cases, you may want to retrieve a specific secret provider from the store because that secret provider has some functionality that the other providers don't have.

In those cases, you can register your secret provider with a unique name so that, in a later stage, you can retrieve back your named provider.

## Registering a named secret provider

Lets consider that you want explicitly use the built-in environment variables secret provider.
First, the secret provider has to be registered with a unique name. 

```csharp
.ConfigureSecretStore((config, stores) =>
{
    stores.AddEnvironmentVariables(..., name: "environment-variables");
})
```

⚠ The name of the registered secret providers should be unique; otherwise, an exception will be thrown when you try to access the `GetProvider` or `GetCachedProvider`.

## Retrieving a named secret provider

Now that the named environment variables secret provider is registered, we are able to retrieve this provider in our application.

Instead of injecting `ISecretProvider` in your application to access secrets, we'll inject `ISecretStore` interface to retrieve named secret providers.

```csharp
[ApiController]
   public class OrderController : ControllerBase
   {
       public class OrderController(ISecretStore secretStore)
       {
            // Gets the `ISecretProvider` with the matched name (with either using the `ISecretProvider` as return type or your own generic type).
            var secretprovider = secretStore.GetProvider<EnvironmentVariableSecretProvider>("environment-variables");

            // Gets the `ICachedSecretProvider` with the matched name (with either using the `ICachedSecretProvider` as return type or your own generic type).
            // Mark that this only works when the secret provider was regisered as a cached secret provider.
            ICachedSecretProvider cachedSecretProvider = secretStore.GetCachedProvider("your-cached-secret-provider");
       }
   }
```

> Note that the name of the registered `ISecretProvider` should be unique; otherwise and exception will be thrown when you try to access the `GetProvider` or `GetCachedProvider`.
