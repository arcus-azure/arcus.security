---
title: "HashiCorp Vault"
layout: default
---

# HashiCorp Vault secret provider
HashiCorp Vault secret provider brings secrets from the KeyValue secret engine to your application.

:::warning
Does not support synchronous secret retrieval via `.GetSecret("<secret-name>")`.
:::

## Installation
Adding secrets from HashiCorp Vault into the secret store requires following package:

```powershell
PM > Install-Package Arcus.Security.Providers.HashiCorp
```

## Configuration
After installing the package, the additional extensions becomes available when building the secret store.

```csharp
var builder = Host.CreateDefaultBuilder(args);
builder.ConfigureSecretStore((_, store) =>
{
    IAuthMethodInfo authMethod = new TokenAuthMethodInfo("MY_VAULT_TOKEN");
    var settings = new VaultClientSettings("https://MY_VAULT_SERVER:8200", authMethod);
    
    store.AddHashiCorpVault(settings, "<secret-path>");
    store.AddHashiCorpVault(.., options =>
    {
        // The point where HashiCorp Vault KeyVault secret engine is mounted.
        // (Default: "kv-v2")
        options.KeyValueMountPoint = "my-kv";

        // The HashiCorp Vault key value secret engine version.
        // (Default: V2)
        options.KeyValueVersion = VaultKeyValueSecretEngineVersion.V1; 
    });
});
```