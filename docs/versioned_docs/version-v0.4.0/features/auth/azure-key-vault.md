---
title: "Authentication for Azure Key Vault"
layout: default
---

# Authentication

As of today we support a few  authentication mechanisms.

## Managed Service Identity

You can use [Managed Service Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) to delegate the authentication to Azure via `ManagedServiceIdentityAuthenticator`.

This is the recommended approach to interact with Azure Key Vault.

```csharp
var vaultAuthenticator = new ManagedServiceIdentityAuthenticator();
var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
var keyVaultSecretProvider = new KeyVaultSecretProvider(vaultAuthenticator, vaultConfiguration);
```

If you require more control over the authentication mechanism you can optionally specify an `AzureServiceTokenProvider` connection string &/or Azure AD instance.

```csharp
var connectionString = Configuration.GetConnectionString("Arcus:MSI:ConnectionString");
var azureAdInstance = Configuration.GetValue<string>("Arcus:MSI:AzureAdInstance");
var vaultAuthenticator = new ManagedServiceIdentityAuthenticator(connectionString, azureAdInstance);
var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
var keyVaultSecretProvider = new KeyVaultSecretProvider(vaultAuthenticator, vaultConfiguration);
```
See [Service-to-service authentication to Azure Key Vault using .NET - Connection String Support](https://docs.microsoft.com/en-us/azure/key-vault/service-to-service-authentication#connection-string-support) for supported connection strings and [National clouds - Azure AD authentication endpoints](https://docs.microsoft.com/en-us/azure/active-directory/develop/authentication-national-cloud#azure-ad-authentication-endpoints) for valid azure AD instances


## Service Principle

Authentication via username and password is supported with the `ServicePrincipalAuthenticator`.

```csharp
var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");

var vaultAuthenticator = new ServicePrincipalAuthenticator(clientId, clientKey);
var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
var keyVaultSecretProvider = new KeyVaultSecretProvider(vaultAuthenticator, vaultConfiguration);
```

## Certificate

Authentication via client ID and certificate is supported with the `CertifidateBasedAuthentication`.

```csharp
var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
X509Certificate2 certificate = ...

var vaultAuthenticator = new CertificateBasedAuthentication(clientId, certificate);
var vaultConfiguration = new KeyVaultConfiguration(keyVaultUri);
var keyVaultSecretProvider = new KeyVaultSecretProvider(vaultAuthenticator, vaultConfiguration);
```
