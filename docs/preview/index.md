---
title: "Home"
layout: default
permalink: /
redirect_from:
 - /index.html
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
- **Interacting with Secrets**
    - [General](features/secrets/general)
    - [Secret store integration](features/secrets/secret-store-integration)
      - [Create new secret source](features/secrets/create-new-secret-source)
    - [Consume from Azure Key Vault](features/secrets/consume-from-key-vault)
        - [Key Vault secret source](features/key-vault/extensions/key-vault-secret-source)
- **Authentication**
    - [Azure Key Vault](features/auth/azure-key-vault)

# License
This is licensed under The MIT License (MIT). Which means that you can use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the web application. But you always need to state that Codit is the original author of this web application.

*[Full license here](https://github.com/arcus-azure/arcus.security/blob/master/LICENSE)*

# Older versions

- [v1.1.0](v1.1.0)
- [v1.0.0](v1.0.0)
- [v0.4.0](v0.4.0)
- [v0.3.0](v0.3.0)
- [v0.2.0](v0.2.0)
- [v0.1.0](v0.1.0)
