---
title: "Arcus - Security"
layout: default
slug: /
sidebar_label: Welcome
sidebar_position: 1
---

# Introduction

Arcus Security allows you to work easily with secrets. Instead of retrieving sensitive information from your application's configuration, Arcus Security allows you to retrieve secrets from a configured **Secret Store**. The secret store supports multiple secret providers to get its secrets from, like Azure Key Vault, HashiCorp, etc. and allows you to write your own secret provider.

Additionally, Arcus Security makes sure that retrieved secrets are cached for a while so to avoid multiple calls to the backing secret provider, which prevents throttling.

![Arcus secret store integration example](/img/arcus-secret-store-diagram.png)

# Guidance
* [Add Arcus secret store with Azure Key vault integration](02-Guides/add-secret-store-with-keyvault-integration.md)

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

# License
This is licensed under The MIT License (MIT). Which means that you can use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the web application. But you always need to state that Codit is the original author of this web application.

*[Full license here](https://github.com/arcus-azure/arcus.security/blob/master/LICENSE)*
