---
title: "Consuming Azure Key Vault secrets"
layout: default
---

# Consuming Azure Key Vault secrets

![](https://img.shields.io/badge/Available%20starting-v0.1-green?link=https://github.com/arcus-azure/arcus.security/releases/tag/v0.1.0)

You can easily create a Key Vault secret provider - The only thing you need to do is specify how you want to configure and to what vault.

```csharp
var vaultAuthentication = new ManagedServiceIdentityAuthenticator();
var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
var keyVaultSecretProvider = new KeyVaultSecretProvider(vaultAuthentication, vaultConfiguration)
```

You can find a list of supported authentication schemes for Azure Key Vault [here](./../../auth/azure-key-vault).

[&larr; back](/)
