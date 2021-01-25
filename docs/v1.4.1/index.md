---
title: "Home"
layout: default
---

[![NuGet Badge](https://buildstats.info/nuget/Arcus.Security.All?packageVersion=1.4.1)](https://www.nuget.org/packages/Arcus.Security.All/1.4.1)

# Installation

We provide a NuGet package per provider and area.

Here is how you install all Arcus Security packages
```shell
PM > Install-Package Arcus.Security.All --Version 1.4.1
```

Here is how you consume secrets for Azure Key Vault:
```shell
PM > Install-Package Arcus.Security.Providers.AzureKeyVault
```

# Features
- **Using a Secret Store**
  - [What is it?](features/secret-store/)
  - Providers
    - [Azure Key Vault](features/secret-store/provider/key-vault)
    - [Configuration](features/secret-store/provider/configuration)
    - [Docker secrets](features/secret-store/provider/docker-secrets)
    - [Environment variables](features/secret-store/provider/environment-variables)    
    - [HashiCorp Vault](features/secret-store/provider/hashicorp-vault)
    - [User Secrets](features/secret-store/provider/user-secrets)
  - [Creating your own secret provider](features/secret-store/create-new-secret-provider)
- **Interacting with Secrets**
    - [General](features/secrets/general)
    - [Consume from Azure Key Vault](features/secrets/consume-from-key-vault)
    - [Authenticate with Azure Key Vault](features/auth/azure-key-vault)

# License
This is licensed under The MIT License (MIT). Which means that you can use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the web application. But you always need to state that Codit is the original author of this web application.

*[Full license here](https://github.com/arcus-azure/arcus.security/blob/master/LICENSE)*

# Older versions

- [v1.4.0](../v1.4.0)
- [v1.3.0](../v1.3.0)
- [v1.1.0](../v1.1.0)
- [v1.0.0](../v1.0.0)
- [v0.4.0](../v0.4.0)
- [v0.3.0](../v0.3.0)
- [v0.2.0](../v0.2.0)
- [v0.1.0](../v0.1.0)
