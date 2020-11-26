---
title: "Configuration secret provider"
layout: default
---

# Configuration secret provider
Configuration secret provider brings you all registered configuration providers of .NET Core by using `IConfiguration` to your application.

> :warning: When using configuration secret provider, it will look for secrets in all configuration sources which is not secure. This provider should only be used for development.

## Installation
The configuration secret provider is built-in as part of the package [Arcus.Security.Core](https://www.nuget.org/packages/Arcus.Security.Core).

## Configuration

```csharp
public class Program
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args)
    {    
        return Host.CreateDefaultBuilder(args)
                   .ConfigureAppConfiguration((context, config) => 
                   {
                       config.AddJsonFile("appsettings.json")
                             .AddJsonFile("appsettings.Development.json");
                   })
                   .ConfigureSecretStore((HostBuilderContext context, IConfiguration config, SecretStoreBuilder builder) =>
                   {
#if DEBUG
                       // Uses the built `IConfiguration` as a secret provider.
                       builder.AddConfiguration(config);

                       // Uses the built `IConfiguration` as secret provider, using `:` instead of `.` when looking up secrets.
                       // Example - When looking up `Queue.Name` it will be changed to `queue:name`.
                       builder.AddConfiguration(config, mutateSecretName: secretName => secretName.Replace(".", ":").ToLower());

                       // Providing an unique name to this secret provider so it can be looked up later.
                       // See: "Retrieve a specific secret provider from the secret store"
                       builder.AddConfiguration(..., name: "Configuration");
#endif
                   });
                   .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```
