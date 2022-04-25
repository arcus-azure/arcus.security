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

# Raw secrets
In some scenarios you'd like to just get the secret value directly without any metadata.
This is possible by calling the `...Raw...` variants on the `ISecretProvider` implementations.

```csharp
string secretValue = await secretProvider.GetRawSecretAsync("EventGrid-AuthKey");
```

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
After a hard refresh you can use the latest secret again and proceed your work.

```csharp
Secret secret = await cachedSecretProvider.GetSecretAsync("EventGrid-AuthKey", ignoreCache: true);
```

## Invalidates a secret from the cache
In some scenarios you'd like to remove a cache entry so that the secret will be retrieved from the provider when a new lookup will be done.

This is useful for scenario's where the secret is updated and you need to tell the cache somehow.

```csharp
await cachedSecretProvider.InvalidateSecretAsync("EventGrid-AuthKey");
```

