---
title: "Secret store integration"
layout: default
---

# Using Secret Store
As alternative to the usage of placing secrets into an `IConfiguration` instance in your application, the `Arcus.Security.Core` package provides a alternative concept called 'secret stores'.
We provide an approach similar to how `IConfiguration` is built, but with a focus on secrets. You can pick and choose the secret providers you want to use and we'll get the job done!

Once register, you can fetch all secrets by using `ISecretProvider` which will get secrets from all the different registered secret providers.

## Installation
For this feature, the following package needs to be installed:

```shell
PM > Install-Package Arcus.Security.Core
```

## Usage
The secret stores are configured during the initial application build-up in the `Program.cs`:

```csharp
public class Program
{
    public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((context, config) => 
                {
                    config.AddJsonFile("appsettings.json")
                          .AddJsonFile("appsettings.Development.json");
                })
                .ConfigureSecretStore((context, config, builder) =>
                {
                    builder.AddEnvironmentVariables();
                })
                .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

Once the secret providers are defined, the `ISecretProvider` can be used as any other registered service:

```csharp
[ApiController]
public class HealthController : ControllerBase
{
    public HealthController(ISecretProvider secretProvider)
    {
    }
}
```

## Built-in secret sources
Several built in secret sources available in the package.

If you require an additional secret sources that aren't available here, please [this document](./create-new-secret-source) that describes how you can create your own secret soure.

**Environment variables**
Using the environment variable secret source, the secrets will be searched in the the variables on the evnvironment.

```csharp
.ConfigureSecretStore((context, config, builder) =>
{
    builder.AdEnvironmentVariables();
})
```

**IConfiguration**
The entire built-up `IConfiguration` can be used as a secret source so secrets will be searched also in all the registered configuration sources.

```csharp
.ConfigureAppConfiguration((context, config) => 
{
    config.AddJsonFile("appsettings.json")
          .AddJsonFile("appsettings.Development.json");
})
.ConfigureSecretStore((HostBuilderContext context, IConfiguration config, SecretStoreBuilder builder) =>
{
    builder.AddConfiguration(config);
});
```

**Azure Key Vault**
Adding Azure Key Vault secrets to the secret store is not built-in, but available in another package.
See [this specific](../key-vault/extensions/key-vault-secret-source) page for more information.

[&larr; back](/)
