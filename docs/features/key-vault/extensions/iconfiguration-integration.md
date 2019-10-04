---
title: "Replace configuration tokens with ISecretProvider"
layout: default
---

# Replace configuration tokens with ISecretProvider

When building your IConfiguration, you can use the extension .AddAzureKeyVault to pass in your `ISecretProvider` instead of using the built-in [Azure Key Vault provider](https://docs.microsoft.com/en-us/aspnet/core/security/key-vault-configuration?view=aspnetcore-2.2#packages).

## Installation

This feature requires to install our NuGet package

```shell
PM > Install-Package Arcus.Security.Providers.AzureKeyVault
```

## Usage
Example how the configuration builder is used inside a web application:

```csharp
IKeyVaultAuthentication vaultAuthentication = new ManagedServiceIdentityAuthentication();
IKeyVaultConfiguration vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
ISecretProvider yourSecretProvider = new KeyVaultSecretProvider(vaultAuthentication, vaultConfiguration);

var config = new ConfigurationBuilder()
    .AddAzureKeyVault(yourSecretProvider)
    .Build();

var host = new WebHostBuilder()
    .UseConfiguration(config)
    .UseKestrel()
    .UseStartup<Startup>();
```

Note that the above codesample does not provide any caching capabilities.  In contrary to the `AzureKeyVaultConfigurationProvider`, the `Arcus.KeyVaultSecretProvider` does not cache retrieved secrets nor does it retrieve all secrets from KeyVault upfront as the `AzureKeyVaultConfigurationProvider` does.  Each time a secret is requested, it will be fetched from KeyVault.

To provide caching capabilities, you can make use of the `CachedSecretProvider` as shown below:

```csharp
IKeyVaultAuthentication vaultAuthentication = new ManagedServiceIdentityAuthentication();
IKeyVaultConfiguration vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
ISecretProvider yourSecretProvider = new KeyVaultSecretProvider(vaultAuthentication, vaultConfiguration);

var config = new ConfigurationBuilder()
    .AddAzureKeyVault(new CachedSecretProvider(yourSecretProvider))
    .Build();

var host = new WebHostBuilder()
    .UseConfiguration(config)
    .UseKestrel()
    .UseStartup<Startup>();
```

[&larr; back](/)
