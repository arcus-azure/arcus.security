---
title: "Configuration secret provider"
layout: default
---

# Configuration secret provider
Configuration secret provider brings you all registered configuration providers of .NET Core by using `IConfiguration` to your application.

> Be careful of using the configuration as a place to store secrets. Please use this only for local development.

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
                       builder.AddConfiguration(config);
                   });
                   .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```
