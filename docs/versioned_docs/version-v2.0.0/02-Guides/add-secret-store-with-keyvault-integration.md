---
title: "Add secret store with Azure Key Vault integration"
layout: default
---

# Add secret store with Azure Key Vault integration
The Arcus secret store is a alternative on the general usage of storing secrets in the application configuration (`IConfiguration`). It is important in application development to differentiate between configuration data and sensitive information like secrets. The Arcus secret store is extremely flexible and can be extended to support several secret providers to retrieve its secrets - both built-in as well as custom.

The secret store can be added during any part of de application lifetime. Once added, you can benefit from the safe and convenient way of secret retrieval that is the Arcus secret store.

This user guide will cover how the Arcus secret store can be added to an existing API application in order to retrieve secrets from Azure Key Vault.

## Terminology
To fully understand the power of the secret store, some terminology has to be understood:
- **Secret**: piece of sensitive information like access keys or connection strings; anything that is private and cannot be made public
- **Secret store**: central place where the application retrieve its secrets.
- **Secret provider**: implementation that provides secrets to the secret store (ex.: Azure Key Vault secret provider), many secret providers can be configured within a secret store.

## Sample application
In this user guide, a fictive API application will be used to add the secret store to. We will be working with two major parts.

The initial place where the application will be started:
```csharp
public class Program
{
    public static void Main(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddJsonFile("appsettings.json");

        WebApplication app = builder.Build();
        app.UseRouting();
        app.Run();
    }
}
```

And the API controller where a secret is being used:
```csharp
[ApiController]
public class OrderController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public OrderController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpPost]
    public async Task Post([FromBody] Order order)
    {
        string connectionString = _configuration["Azure:ServiceBus:ConnectionString"];

        // Post Order to Azure Service Bus...
    }
}
```

> Note that in this example, we use the application configuration to retrieve the Azure Service Bus connection string to post the incoming order to Azure Service Bus and not the Arcus secret store.

## Use Arcus secret store
For us to move away from the application configuration, we need to make use of the Arcus secret store. The following step instructions will guide you in this process:

### 1. Install Arcus security
For this example, we will be using Azure Key Vault as our single secret provider in the secret store, so we can install this directly:
```shell
PM > Install-Package Arcus.Security.Providers.AzureKeyVault
```

> Note that this package depends on the `Arcus.Security.Core` package, where the secret store exists.

### 2. Add Arcus secret store to application
Once the package is installed, add the secret store via extensions to the API application:
* 2.1 Use the `.ConfigureSecretStore` to setup the secret store with necessary secret providers
* 2.2 Use the the `.AddAzureKeyVaultWithManagedIdentity` to add the Azure Key Vault secret provider to the secret store

```csharp
using Arcus.Security.Core.Caching.Configuration;

public class Program
{
    public static void Main(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddJsonFile("appsettings.json");

        builder.Host.ConfigureSecretStore((configuration, stores) =>
        {
            string vaultUri = configuration["Azure:KeyVault:VaultUri"];
            stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, CacheConfiguration.Default);
        });

        WebApplication app = builder.Build();
        app.UseRouting();
        app.Run();
    }
}
```

> Note that during the configuration of the secret store, you will be able to access the application configuration; in this case it is used to retrieve the URI where the Azure Key Vault is located.

### 3. Inject the Arcus secret store in application
Now that the Arcus secret store is added and configured to the application, the application can use it to retrieve it secrets. The Arcus secret store is accessible throughout the application via the `ISecretProvider` interface - combining all the configured secret providers.

In the `OrderController`, inject the `ISecretProvider` interface via the constructor.  The `ISecretProvider` will allow you to retrieve the Azure Service Bus connection string from the secret store.
```csharp
using Arcus.Security.Core;

[ApiController]
public class OrderController : ControllerBase
{
    private readonly ISecretProvider _secretProvider;

    public OrderController(ISecretProvider secretProvider)
    {
        _secretProvider = secretProvider;
    }

    [HttpPost]
    public async Task Post([FromBody] Order order)
    {
        string connectionString = await _secretProvider.GetRawSecretAsync("Azure_ServiceBus_ConnectionString");

        // Post Order to Azure Service Bus...
    }
}
```

## Conclusion
In this user guide, you've seen how the Arcus secret store can be added to an existing application to retrieve secrets. The Arcus secret store is a very wide topic and can be configured with many different options. See [this documentation page](../03-Features/secret-store/index.md) to learn more about the Arcus secret store.

## Further reading
- [Arcus secret store documentation](../03-Features/secret-store/index.md)
  - [Azure Key Vault secret provider](../03-Features/secret-store/provider/key-vault.md)
  - [Create your own secret provider](../03-Features/secret-store/create-new-secret-provider.md)
- [Introducing Arcus secret store](https://www.codit.eu/blog/introducing-secret-store-net-core/)
- [The power of the Arcus secret store](https://www.codit.eu/blog/the-power-of-the-arcus-secret-store/)
- [Role-based authorization by low-level customization of the Arcus secret store](https://www.codit.eu/blog/role-based-authorization-low-level-customization-arcus-secret-store/)