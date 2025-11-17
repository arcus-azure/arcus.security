---
title: "Arcus - Security"
layout: default
slug: /
sidebar_label: Welcome
sidebar_position: 1
---

# Introduction
Welcome to the Arcus Security site! 🎉

## What is Arcus Security?
Arcus Security is an umbrella term for a set of NuGet packages `Arcus.Security.*` that help with the interaction of secrets in your application. It provides caching, secret name mapping and registration system to include one or more secret sources (Azure Key Vault, HashiCorp Vault, etc.).

## Why should I use Arcus Security?
Secrets should never be logged or stored in plain text, should be cached to handle throttling. While the Microsoft application configuration system is a way to provide secrets in your application, it does not make the distinction between a configuration value and a secret. Making it the sole responsibility of the developer to remember they are dealing with a secret.

Arcus Security makes this distinction explicit by removing the secrets from the application configuration and placing them in something called a 'secret store'. [Read more about this idea](https://www.codit.eu/blog/introducing-secret-store-net-core/).

## How to to use Arcus Security?
See our dedicated [getting started](./getting-started.md) page to take your first steps with Arcus Security.

# License
This is licensed under The MIT License (MIT). Which means that you can use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the web application. But you always need to state that Codit is the original author of this web application.

*[Full license here](https://github.com/arcus-azure/arcus.security/blob/master/LICENSE)*
