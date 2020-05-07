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
string secretVersion = secret.Version
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
var cachedSecretProvider = new KeyVaultSecretProvider(vaultAuthenticator, vaultConfiguration)
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

## Forcing a secret refresh

In some scenarios you'd like to skip the cache and do a hard refresh by looking it up in the provider.

This is important because in certain scenarios your secrets can be rolled and thus you will be revoked access.
After a hard refresh you can use the latest secret again and proceed your work.

```csharp
Secret secret = await cachedSecretProvider.GetSecretAsync("EventGrid-AuthKey", ignoreCache: true);
```

[&larr; back](/)