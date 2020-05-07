---
title: "Consuming Azure Key Vault secrets"
layout: default
---

# Consuming Azure Key Vault secrets

You can easily create a Key Vault secret provider - The only thing you need to do is specify how you want to configure and to what vault.

```csharp
var vaultAuthentication = new ManagedServiceIdentityAuthentication();
var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
var keyVaultSecretProvider = new KeyVaultSecretProvider(vaultAuthentication, vaultConfiguration)
```

You can find a list of supported authentication schemes for Azure Key Vault [here](./../../auth/azure-key-vault).

[&larr; back](/)
