---
title: "Arcus - Security"
layout: default
slug: /
sidebar_label: Welcome
sidebar_position: 1
---

# Installation

We provide a NuGet package per provider and area.

Here is how you install all Arcus Security packages
```shell
PM > Install-Package Arcus.Security.All
```

Here is how you consume secrets for Azure Key Vault:
```shell
PM > Install-Package Arcus.Security.Providers.AzureKeyVault
```

# Features
- **Using a Secret Store**
  - [What is it?](features/secret-store/)
  - [Use within Azure Functions](features/secret-store/azure-functions)
  - Providers
    - [Azure Key Vault](features/secret-store/provider/key-vault)
    - [Command line arguments](features/secret-store/provider/cmd-line)
    - [Configuration](features/secret-store/provider/configuration)
    - [Docker secrets](features/secret-store/provider/docker-secrets)
    - [Environment variables](features/secret-store/provider/environment-variables)
    - [HashiCorp Vault](features/secret-store/provider/hashicorp-vault)
    - [User Secrets](features/secret-store/provider/user-secrets)
  - Advanced
    - [Retrieve specific secret provider](features/secret-store/named-secret-providers)
    - [Creating your own secret provider](features/secret-store/create-new-secret-provider)
- **Interacting with Secrets**
    - [General](features/secrets/general)
    - [Consume from Azure Key Vault](features/secrets/consume-from-key-vault)
    - [Authenticate with Azure Key Vault](features/auth/azure-key-vault)

# License
This is licensed under The MIT License (MIT). Which means that you can use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the web application. But you always need to state that Codit is the original author of this web application.

*[Full license here](https://github.com/arcus-azure/arcus.security/blob/master/LICENSE)*
