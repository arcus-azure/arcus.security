# Migrate your application from Arcus.Security v2.x to v3
This guide will walk you through the process of migrating your application from Arcus.Security v2 to the new major v3 release.

## General
* 🗑️ .NET 6 support is removed. All Arcus.Security.* packages support .NET 8 and stop supporting .NET 6. (.NET 10 support starts from v2.1.)
* 🗑️ Transient GuardNET dependency is replaced by built-in argument checking.
* 🗑️ Transient Arcus.Observability dependency for auditing is removed.
* ✏️ The new main core types are now under the `Arcus.Security` namespace, instead of previously the `Arcus.Security.Core` namespace. Following types in the old namespace are removed:
  * `ISecretProvider` (in favor of `Arcus.Security.ISecretProvider`)
  * `ISecretStore` (in favor of `Arcus.Security.ISecretStore`)
  * `IVersionedSecretProvider`
  * `ISyncSecretProvider`
  * `(I)CachedSecretProvider`
  * `(I)CacheConfiguration`
  * `CriticalExceptionFilter`
  * `SecretAuditingOptions`
  * `SecretStoreSource`
  * `SecretProviderOptions`
  * `SecretNotFoundException`
  * `MutatedSecretNameSecretProvider`
  * `MutatedSecretNameCachedSecretProvider`

## 🎯 Use `ISecretStore` instead of `ISecretProvider` as the secret store's main point of contact
Starting from v3, accessing the secret store now happens via the `Arcus.Security.ISecretStore` interface (in new namespace), instead of previously using the same `Arcus.Security.Core.ISecretProvider` interface as for the external secret provider implementations.

```diff
- using Arcus.Security.Core;
+ using Arcus.Security;

// ⬇️ Injected into the application
- ISecretProvider store = ...
+ ISecretStore store = ...
```

### `Secret` ➡️ `SecretResult`
Before v3, failures in the secret store were communicated via exceptions. Starting from v3, the secret store returns a result type that represents a successful/failed interaction with the store.

```diff
- try
- {
-     Secret secret = await store.GetSecretAsync("<name>");
-     string secretValue = secret.Value;

+     SecretResult result = await store.GetSecretAsync("<name>");
+     if (result.IsSuccess)
+     {
+         string secretValue = result.Value;
+     }
- }
- catch (SecretNotFoundException exception)
- {    
- }
```

:::info
The `SecretResult.Failure` enumeration has two members: `NotFound` in case a secret could not be retrieved from any of the registered secret providers, and `Interrupted` in case an exception was thrown by one of the secret providers during secret retrieval.
:::

This also means that there is no need for 'critical exceptions' that users could previously register on the store to signal non-transient failures (e.g. authentication problems). The following types/members are removed:
* 🗑️ `CriticalExceptionFilter`
* 🗑️ `SecretStoreBuilder.AddCriticalException<...>(...)`

Custom secret providers can use the `SecretResult` model in case of interrupted/non-transient failures.

### 🚛 Move caching from providers to store
Caching is centralized on the secret store instead of spread across secret providers. Just as before v3, caching happens internally, only now custom secret providers are registered without any mentioning of secret caching.

This affects the existing caching-types and (extension) members, which are removed/unavailable in v3:
* 🗑️ `(I)CachedSecretProvider`
* 🗑️ `(I)CacheConfiguration`
* 🗑️ `.WithCaching(...)` on secret provider
* 🗑️ `.GetCachedProvider(...)` on secret store.

```diff
services.AddSecretStore(store =>
{
    var cacheDuration = TimeSpan.FromMinutes(5);
-   store.AddProvider(new MySecretProvider().WithCaching(cacheDuration));
+   store.AddProvider(new MySecretProvider());
+   store.UseCaching(cacheDuration);
});
```

Ignoring the cache at secret retrieval-time can still be done via a new method overload on the `ISecretStore` instead on the secret provider itself.

```diff
- using Arcus.Security.Core.Caching;
- using Arcus.Security.Core;
+ using Arcus.Security;

ISecretStore store = ...

- ICachedSecretProvider provider = store.GetCachedProvider("Admin secrets");
- Secret secret = await provider.GetSecretAsync("<name>", ignoreCache: true);
+ SecretResult result = await store.GetSecretAsync("<name>", options =>
+ {
+     options.UseCache = false;
+ });
```

Invalidating a secret within a custom secret provider now happens via the `ISecretStoreContext` that can be passed upon creating the provider.

```diff
- public class MySecretProvider : ICachedSecretProvider
+ public class MySecretProvider(ISecretStoreContext context) : ISecretProvider
{
    public async Task SetSecretAsync(string name, string value)
    {
        // Implementation omitted.

-       await InvalidateSecretAsync(name);
+       await context.Cache.InvalidateSecretAsync(name);
    }

-   public Task InvalidateSecretAsync(string secretName) { ... }

    // Implementation omitted.
}
```

### 🗑️ Removed `GetRawSecret*` overloads
Starting from v3, there is no distinction anymore between 'secrets' and 'raw secrets' (meaning: directly accessing the secret's value). All secret interactions happen via the asynchronous/synchronous `GetSecret(Async)` methods on the `ISecretStore`.

:::tip[implicit overload on `SecretResult`]
There exists an `implicit operator` overload on the `SecretResult`, which means that that secret retrievals can also be written without checking for failures.
```csharp
string secretValue = await store.GetSecretAsync("<name>");
```
Just be aware that in case of a failure, an exception will still be thrown.
:::

### 🗑️ Removed `GetVersionedSecrets*` overloads
Starting from v3, there is no general way of retrieving versioned secrets via the secret store anymore. Secret versioning is highly dependent on the secret provider implementation, which makes a general way of contacting rather troublesome.

Our Azure Key Vault secret provider is the only provider that supports secret versioning, that is why we introduced a new `GetVersionedSecretsAsync` operation on the `KeyVaultSecretProvider` that can be used as alternative.

```diff
var provider = store.GetProvider<KeyVaultSecretProvider>("Admin secrets");

int amountOfVersions = 3;
- IEnumerable<Secret> secrets = await provider.GetSecretsAsync("<name>", amountOfVersions);
+ SecretsResult result = await provider.GetVersionedSecretsAsync("<name>", amountOfVersions);
```

:::info
The `SecretsResult` acts the same way as the `SecretResult`, only for a collection of secrets (implements `IEnumerable<SecretResult>`).
```csharp
SecretsResult result = ...
IEnumerable<SecretResult> secrets = result.ToArray();
```
:::

## 🚛 Moved secret provider options
Additional options on any of the Arcus-provided secret providers are now available via alternative overloads.

```diff
store.AddSecretStore(store =>
{
-    store.AddEnvironmentVariables(
-        name: "Development secrets",
-        mutateSecretName: secretName => secretName.ToUpper());
+    store.AddEnvironmentVariables(options =>
+    {
+        options.ProviderName = "Development secrets";
+        options.MapSecretName(secretName => secretName.ToUpper());   
+    })
});
```

:::info[all secret provider-specific options are now consolidated]
Additional options, specific for secret provider implementations (e.g. 'Prefix` for environment variables) are now also consolidated into a single options model together with the common options 'name' and 'secret name mapping'.
:::

:::tip[provider name default filled-out]
By default, any secret provider registered in the secret store gets a provider name assigned. If the user does not provide one, the type name is used. This helps better with defect localization and logging -- which is also greatly improved in v3. 
:::

## 🧩 Implementing a custom secret provider differently
The v3 uses a different `ISecretProvider` interface in the `Arcus.Security` namespace. Different than the previous `Arcus.Security.Core.ISecretProvider`, is that it now always support synchronous/asynchronous operations (previously, there existed an `ISyncSecretProvider` to do synchronous secret operations). Implementing a custom secret provider should therefore take this into account.

```diff
- using Arcus.Security.Core;
+ using Arcus.Security;

public class MySecretProvider : ISecretProvider
{
-    public Task<Secret> GetSecretAsync(string secretName) { ... }
-    public Task<string> GetRawSecretAsync(string secretName) { ... }
+    public Task<SecretResult> GetSecretAsync(string secretName) { ... }
+    public SecretResult GetSecret(string secretName) { ... }
}
```

:::tip[default asynchronous implementation]
The new `ISecretProvider` has a default `Task.FromResult(GetSecret(...))` interface implementation for the asynchronous operation. Which means that synchronous-only secret providers only need to implement the `GetSecret(...)` member.
:::

> 🔗 For custom options on your secret provider, see the [dedicated feature documentation page](../03-Features/secret-store/custom-secret-provider.md). This page also talks about how custom secret provider implementations and interact with the secret store cache.

:::warning[extending existing secret providers]
In v3, we stopped the support for extending existing secret providers with inheriting. Mostly because due to the internal refactoring and simplification of the secret store, extending providers becomes unnecessary.
:::

## 🗑️ Removed secret auditing with Arcus.Observability
There is no built-in secret auditing anymore in v3 using Arcus.Observability's custom event tracking. This means that no such options can be configured anymore on the secret store and that `Arcus.Observability` is removed from the transient dependencies.

```diff
services.AddSecretStore(store =>
{
-    store.WithAuditing(...);
})
```

## Secret provider implementations
### `KeyVaultSecretProvider.StoreSecretAsync` ➡️ `.SetSecretAsync`
Storing a secret in Azure Key Vault with the `KeyVaultSecretProvider` happens now with the more streamlined `.SetSecretAsync(...)` method.

```diff
- using Arcus.Security.Core;
+ using Arcus.Security;
using Arcus.Security.Providers.AzureKeyVault;

ISecretStore store = ...
var provider = store.GetProvider<KeyVaultSecretProvider>("Admin secrets");

- Secret newSecret = await provider.StoreSecretAsync("<name>", "<new-value>");
+ SecretResult result = await provider.SetSecretAsync("<name>", "<new-value>");
```