---
title: "Custom secret provider"
layout: default
sidebar_position: 3
---

# Create a custom secret provider
The secret store allows you to create custom secret provider implementations for external source for which no implementation exists yet, or if you want to fully control how secrets are retrieved.

This page describes how you develop, configure and finally register your custom secret provider implementation into the secret store. In this example, a new secret provider is developed for the Windows Registry.

## Implement the `ISecretProvider` interface
:::note
The `ISecretProvider` interface is available either transient via one of the secret provider NuGet packages, or directly via the [`Arcus.Security.Core`](https://www.nuget.org/packages/Arcus.Security.Core) package.
:::

```csharp
using Arcus.Security;
using Microsoft.Win32;

public class RegistrySecretProvider(ILogger<RegistrySecretProvider> logger) : ISecretProvider
{
    public SecretResult GetSecret(string secretName)
    {
        try
        {
            object value = Registry.LocalMachine.GetValue(secretName);
            return value is null
                ? SecretResult.NotFound(secretName, "no secret found in Windows Registry")
                : SecretResult.Success(secretName, value.ToSTring());
        }
        catch (SecurityException exception)
        {
            logger.LogError(exception, "Windows Registry secret '{SecretName}' failed to be retrieved due to lacking permissions", secretName);
            return SecretResult.Interrupted(secretName, "secret not available in Windows Registry due to lacking permissions", exception);
        }
    }

    public Task<SecretResult> GetSecretAsync(string secretName)
    {
        SecretResult result = GetSecret(secretName);
        return Task.FromResult(result);
    }
}
```

Make sure to use the factory methods on `SecretResult` correctly based on the external situation.
:::tip[default implementation]
The `ISecretProvider` implements the asynchronous `GetSecretAsync` default with a redirection to the synchronous variant. This means in our example, the `GetSecretAsync` implementation is optional.
:::

## Register using `store.AddProvider(...)` overloads
The secret store has several `.AddProvider(...)` overloads to add (custom) secret providers in its collection. In this case, we only need to inject the logger in our secret provider.

```csharp
var builder = Host.CreateDefaultBuilder(args);
builder.ConfigureSecretStore((configuration, store) =>
{
    store.AddProvider((IServiceProvider provider, _) =>
    {
        var logger = provider.GetRequiredService<ILogger<RegistrySecretProvider>>();
        return new RegistrySecretProvider(logger);

    }, configureOptions: null);
});
```

:::tip[configure built-in options]
As discussed in the [secret store](index.mdx) feature documentation, all registered secret providers have the possibility to configure built-in options, as do custom registrations:
```csharp
store.AddProvider(..., options =>
{
    options.ProviderName = "Windows Registry";
    
    options.MapSecretName(name => name.ToUpper().Replace('.', '_'));
});
```
:::

## Customize all the things

<details>
<summary><h3 style={{ margin:0 }}>🧩 Custom options by extending built-in options</h3></summary>

Most of our available secret providers rely on the built-in options to register themselves. Additional configuration is required when it depends on user input (the `Prefix` option in the environment variables secret provider, to name one).

In our case, we could create an options model to let the user decide in which Windows Registry field they want to search for secrets.
```csharp
public enum WindowsRegistryKey { ClassesRoot, CurrentConfig, CurrentUser, LocalMachine, PerformanceData, Users }

public class RegistrySecretProviderOptions : SecretProviderRegistrationOptions
{
    public RegistrySecretProviderOptions() : base(typeof(RegistrySecretProvider))
    {
    }

    public WindowsRegistryKey RegistryKey { get; set; }
}
```

Using this options model during registration happens with the custom `store.AddProvider<TProvider, TOptions>(...)` overload.
```csharp
store.AddProvider((IServiceProvider provider, _, RegistrySecretProviderOptions options) =>
{
    var logger = provider.GetRequiredService<ILogger<RegistrySecretProvider>>();
    return new RegistrySecretProvider(options, logger);

}, (RegistrySecretProviderOptions options) =>
{
    options.RegistryKey = WindowsRegistryKey.ClassesRoot;
});
```
</details>

<details>
<summary><h3 style={{ margin:0 }}>⚡ Direct secret store access</h3></summary>

Some functionality is handled at a higher level, like caching. To directly access the secret store from your custom secret provider, you can use the `ISecretStoreContext` that gets passed during the registration.

```csharp
store.AddProvider((ISecretProvider provider, ISecretStoreContext context) =>
{
    var logger = provider.GetRequiredService<ILogger<RegistrySecretProvider>>();
    return new RegistrySecretProvider(context, logger);
});
```

In our example, we could introduce a `SetSecretAsync(...)` variant to upsert a new Windows Registry key. This would need the secret store cache to signal that the secret should be invalidated.

```csharp
public class RegistrySecretProvider : ISecretProvider
{
    private readonly ISecretStoreContext _context;

    public RegistrySecretProvider(ISecretStoreContext context, ...)
    {
        _context = context;
    }

    public async Task SetSecretAsync(string secretName, string secretValue)
    {
        Registry.LocalMachine.SetValue(secretName, secretValue);
        // highlight-start
        _context.Cache.InvalidateSecretAsync(secretName);
        // highlight-end
    }
}
```
</details>

## Contribute your secret provider
We are open for contributions and are more than happy to receive pull requests with new secret providers if you feel there is a broader need for it!