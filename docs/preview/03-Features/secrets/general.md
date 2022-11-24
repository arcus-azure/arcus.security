---
title: "Consuming Secrets"
layout: default
---

# Consuming secrets
Every provider implements `ISecretProvider` which makes it easy to use a consistent flow, regardless of the provider.

Secrets can be easily retrieved as follows:

```csharp
Secret secret = await secretProvider.GetSecretAsync("EventGrid-AuthKey");

string secretValue = secret.Value;
string secretVersion = secret.Version;
DateTimeOffset? expirationDate = secret.Expires;
```

## Raw secrets
In some scenarios you'd like to just get the secret value directly without any metadata.
This is possible by calling the `...Raw...` variants on the `ISecretProvider` implementations.

```csharp
string secretValue = await secretProvider.GetRawSecretAsync("EventGrid-AuthKey");
```

## Synchronous secrets
In some scenarios you'd like to retrieve secrets synchronously. A common situation is when you want to register a dependent service into the dependency container that requires a secret, but since such a container only registers instances or synchronous functions, there is no easy way to retrieve a secret asynchronously.

Almost all built-in secret providers we provide support synchronous secret retrieval, only the [HashiCorp Vault secret provider](../secret-store/provider/hashicorp-vault.md) does not support this.

Retrieving synchronous secrets can be done via either using the `ISyncSecretProvider` alternative interface, or by calling the `GetSecret` extensions on an `ISecretProvider` implementation.

```csharp
var services = new ServiceCollection();
services.AddSingleton(serviceProvider =>
{
    // #1 injecting the `ISyncSecretProvider`:
    var syncSecretProvider = serviceProvider.GetRequiredService<ISyncSecretProvider>();
    Secret secret = synSecretProvider.GetSecret("EventGrid-AuthKey");
    string secretValue = syncSecretProvider.GetRawSecret("EventGrid-AuthKey");

    // #2 calling `GetSecret` or `GetRawSecret` extension on `ISecretProvider`:
    var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
    Secret secret = secretProvider.GetSecret("EventGrid-AuthKey");
    string secretProvider = secretProvider.GetRawSecret("EventGrid-AuthKey");

    return new MyDependentService(secretValue);
});
```

⚠ Make sure that you only call the `GetSecret` and `GetRawSecret` extension on `ISecretProvider` implementations that also implement the `ISyncSecretProvider` interface. The [Arcus secret store](../secret-store/index.md) automatically makes sure that you can use this extension on any injected `ISecretProvider` but when no secret provider is registered that supports synchronous secret retrieval, an `SecretNotFoundException` will be thrown nonetheless.

# Caching Secrets
Some secret providers recommend to cache secrets for a while to avoid hitting the service limitations.

We provide a `CachedSecretProvider` which allows the secrets to be cached in memory for a certain amount of time.

```csharp
var cachedSecretProvider = new CachedSecretProvider(secretProvider);
Secret secret = await cachedSecretProvider.GetSecretAsync("EventGrid-AuthKey");
```

If you prefer a more fluent approach you can also use our `WithCaching` extension.

```csharp
var cachedSecretProvider = new KeyVaultSecretProvider(vaultAuthentication, vaultConfiguration)
                                    .WithCaching();
Secret secret = await cachedSecretProvider.GetSecretAsync("EventGrid-AuthKey");
```

## Configuring the cache
By default, retrieved secrets are cached for **5 minutes**, but you can configure this yourself.

```csharp
var cacheConfiguration = new CacheConfiguration(TimeSpan.FromMinutes(10)); // Optional: Default is 5 min
var cachedSecretProvider = new CachedSecretProvider(secretProvider, cacheConfiguration);
Secret secret = await cachedSecretProvider.GetSecretAsync("EventGrid-AuthKey");
```

## Bypassing cached secrets
In some scenarios you'd like to skip the cache and retrieve the secret by looking it up in the secret-store, instead of retrieving it from the cache.

This is important because in certain scenarios your secrets can be rolled and thus you will be revoked access.

```csharp
Secret secret = await cachedSecretProvider.GetSecretAsync("EventGrid-AuthKey", ignoreCache: true);
```

## Invalidates a secret from the cache
In some scenarios you'd like to remove a cache entry so that the secret will be retrieved from the provider when a new lookup will be done.

After a hard refresh you can use the latest secret again and proceed your work. This is useful for scenario's where the secret is updated and you need to tell the cache somehow.

```csharp
await cachedSecretProvider.InvalidateSecretAsync("EventGrid-AuthKey");
```

