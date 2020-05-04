---
title: "Authentication for Azure Key Vault"
layout: default
---

## Authentication

As of today we support a few  authentication mechanisms.

### Managed Service Identity

![](https://img.shields.io/badge/Available%20starting-v0.1-green?link=https://github.com/arcus-azure/arcus.security/releases/tag/v0.1.0)

You can use [Managed Service Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) to delegate the authentication to Azure via `ManagedServiceIdentityAuthenticator`.

```csharp
var vaultAuthenticator = new ManagedServiceIdentityAuthenticator();
var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
var keyVaultSecretProvider = new KeyVaultSecretProvider(vaultAuthenticator, vaultConfiguration);
```

This is the recommended approach to interact with Azure Key Vault.

### Service Principle

![](https://img.shields.io/badge/Available%20starting-v0.1-green?link=https://github.com/arcus-azure/arcus.security/releases/tag/v0.1.0)

Authentication via username and password is supported with the `ServicePrincipalAuthenticator`.

```csharp
var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");

var vaultAuthenticator = new ServicePrincipalAuthenticator(clientId, clientKey);
var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
var keyVaultSecretProvider = new KeyVaultSecretProvider(vaultAuthenticator, vaultConfiguration);
```

### Certificate

![](https://img.shields.io/badge/Available%20starting-v0.2-green?link=https://github.com/arcus-azure/arcus.security/releases/tag/v0.2.0)

Authentication via client ID and certificate is supported with the `CertifidateBasedAuthentication`.

```csharp
var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
X509Certificate2 certificate = ...

var vaultAuthenticator = new CertificateBasedAuthentication(clientId, certificate);
var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
var keyVaultSecretProvider = new KeyVaultSecretProvider(vaultAuthenticator, vaultConfiguration);
```

[&larr; back](/)