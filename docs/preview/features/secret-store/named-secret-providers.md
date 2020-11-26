---
title: "Named secret providers"
layout: default
---

# Retrieve a specific secret provider from the secret store

The default workings of the secret store, is that a set of secret providers are registered and the consumer gets access to all of secrets provided by `ISecretProvider`s.
In some cases, you may want to retrieve a specific secret provider from the store. This can be because that secret provider has some functionality that the other providers doesn't have.

In those cases, you can register your secret provider with a unique name. This name will be matched with the secret provider so that in a later stage, you can retrieve back your named provider.

## Register a named secret provider

First, the secret provider has to be registered with a unique name. 
Let's use this secret provider as an example:

```csharp
public class GetAndSetSecretprovider : ISecretProvider
{
    // From the `ISecretProvider`; so available in the secret store.
    public async Task<Secret> GetSecretAsync(string secretName)
    {
        // Gets the secret...
    }

    // Not from the `ISecretProvider`; so not available in the secret store. 
    public async Task<Secret> SetSecretAsync(string secretName, string secretValue)
    {
        // Sets the secret...
    }
}
```

As you can see, this secret provider has some extra functionality that is not available for us via the secret store.
Now, let's register this secret provider in the secret store:

```csharp
.ConfigureSecretStore((config, stores) =>
{
    stores.AddProvider(new GetAndSetSecretProvider(), options => options.Name = "get/set")
})
```

Note that we can use the `SecretProviderOptions` function here to set our unique name.

## Retrieve the named secret provider

Now that the named secret provider is registered, we should be able to retrieve this provider somewhere else in the application.
Normally, you inject the `ISecretProvider` in your application service and accesses the secrets, but now you'll have to inject the `ISecretStore` interface to access the specific secret store operations.

```csharp
[ApiController]
   public class OrderController : ControllerBase
   {
       public class OrderController(ISecretStore secretStore)
       {
            // Gets the `ISecretProvider` with the matched name (with either using the `ISecretProvider` as return type or your own generic type).
            var secretprovider = secretStore.GetProvider<GetAndSetSecretProvider>("get/set");

            // Gets the `ICachedSecretProvider` with the matched name (with either using the `ICachedSecretProvider` as return type or your own generic type).
            // Mark that this only works when the secret provider was regisered as a cached secret provider.
            ICachedSecretProvider cachedSecretProvider = secretStore.GetCachedProvider("get/set");
       }
   }
```

> Note that the name of the registered `ISecretProvider` should be unique; otherwise and exception will be thrown when you try to access the `GetProvider` or `GetCachedProvider`.