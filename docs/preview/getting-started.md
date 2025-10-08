---
sidebar_label: Getting started
sidebar_position: 2
---

# Getting started with Arcus Security
**Welcome to Arcus Security! 🎉**

This page is dedicated to be used as a walkthrough on how to integrate Arcus Security in new an existing projects. Arcus Security is an umbrella term for a set of `Arcus.Security.*` NuGet packages that makes your application development more secure.

:::note[Used terms]
* **Secret store:** an alternative on Microsoft's application configuration (`IConfiguration`) that acts as a central place in your application to retrieve secrets.
* **Secret provider:** a registration on the **secret store** that retrieves secrets on request from an external source.
:::

## The basics of the secret store
While the **secret store** is abstracted away in a `Arcus.Security.Core` package, consumers of Arcus Security rarely have to deal with this package directly. Instead, there exists a set of `Arcus.Security.Providers.*` packages that each represent a single **secret provider**. Application developers can pick and choose one or more of these provider packages to get started.

Instead of directly interact with Azure Key Vault or environment variables containing secret information, Arcus Security gives you a central interface called `ISecretStore` where all secret retrievals goes through.

```csharp
using Arcus.Security;

var builder = Host.CreateDefaultBuilder(args);
builder.ConfigureServices(services =>
{
    // highlight-start
    services.AddSecretStore(store =>
    {
        store.AddAzureKeyVault(...);
    });
    // highlight-stop

    services.AddDbContext<ContosoDbContext>((serviceProvider, options) =>
    {
        // highlight-start
        var store = serviceProvider.GetRequiredService<ISecretStore>();
        var connectionString = store.GetSecret("Contoso_Sql_ConnectionString");
        // highlight-stop

        options.UseAzureSql(connectionString);
    });
});
```

## Next steps in discovering the secret store
There is a lot more to discover on the **secret store** and how it can benefit your application development process.

* See the [dedicated secret store feature documentation](./03-Features/secret-store/index.md) page to see the full functionality of the **secret store**.
* See the sidebar to learn more about specific **secret providers** like [Azure Key Vault](./03-Features/secret-store/provider/key-vault.md) and [Docker Secrets](./03-Features/secret-store/provider/docker-secrets.md).
* See the [custom secret provider feature documentation](./03-Features/secret-store/custom-secret-provider.md) page to create your own **secret provider**.