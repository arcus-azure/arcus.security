# Arcus - Security
[![Build Status](https://dev.azure.com/codit/Arcus/_apis/build/status/Commit%20builds/CI%20-%20Arcus.Security?branchName=main)](https://dev.azure.com/codit/Arcus/_build/latest?definitionId=727&branchName=main)
[![NuGet Badge](https://buildstats.info/nuget/Arcus.Security.Core?includePreReleases=true)](https://www.nuget.org/packages/Arcus.Security.Core/)
[![codecov](https://codecov.io/gh/arcus-azure/arcus.security/branch/main/graph/badge.svg?token=K42A5X8QMA)](https://codecov.io/gh/arcus-azure/arcus.security)

Security for Azure development in a breeze.

![Arcus](https://raw.githubusercontent.com/arcus-azure/arcus/master/media/arcus.png)

# Installation
Easy to install it via NuGet:

- [**Secret store**](https://security.arcus-azure.net/features/secret-store/): contains the bare bones of the Arcus secret store functionality, including the `ISecretProvider` and other abstractions.

```shell
PM > Install-Package Arcus.Security.Core
```

- **Secret providers**

    - [Azure Key Vault](https://security.arcus-azure.net/features/secret-store/provider/key-vault): contains an implementation to interact with Azure Key Vault via the secret store.
    ```shell
    PM > Install-Package Arcus.Security.Providers.AzureKeyVault
    ```
    - [Command line](https://security.arcus-azure.net/features/secret-store/provider/cmd-line): contains an implementation to handle command line arguments as secrets via the secret store.
    ```shell
    PM > Install-Package Arcus.Security.Providers.CommandLine
    ```
    - [Configuration (built-in)](https://security.arcus-azure.net/features/secret-store/provider/configuration) (with [`IConfiguration`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.configuration.iconfiguration?view=dotnet-plat-ext-6.0)): contains an implementation to handle configuration values as secrets via the secret store.
    - [Docker secrets](https://security.arcus-azure.net/features/secret-store/provider/docker-secrets): contains an implementation to handle file secrets in a Docker environment as secrets via the secret store.
    ```shell
    PM > Install-Package Arcus.Security.Providers.DockerSecrets
    ```
    - [Environment (built-in)](https://security.arcus-azure.net/features/secret-store/provider/environment-variables): contains an implementation to handle environment variables as secrets via the secret store.
    - [HashiCorp](https://security.arcus-azure.net/features/secret-store/provider/hashicorp-vault): contains an implementation to interact with an HashiCorp Vault via the secret store.
    ```shell
    PM > Install-Package Arcus.Security.Providers.HashiCorp
    ```
    - [User secrets](https://security.arcus-azure.net/features/secret-store/provider/user-secrets): contains an implementation to handle user secrets on disk as secrets via the secret store.
    ```shell
    PM > Install-Package Arcus.Security.Providers.UserSecrets
    ```

- **Secret store for Azure Functions**: contains useful extensions to interact more fluently with the secret store in an Azure Functions environment.

```shell
PM > Install-Package Arcus.Security.AzureFunctions
```

For a more thorough overview, we recommend reading [our documentation](#documentation).

# Documentation
All documentation can be found on [here](https://security.arcus-azure.net/).

# Customers
Are you an Arcus user? Let us know and [get listed](https://bit.ly/become-a-listed-arcus-user)!

# License Information
This is licensed under The MIT License (MIT). Which means that you can use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the web application. But you always need to state that Codit is the original author of this web application.

Read the full license [here](https://github.com/arcus-azure/arcus.security/blob/master/LICENSE).
