---
title: "Configuration secret provider"
layout: default
---

# Configuration secret provider
The entire built-up `IConfiguration` can be used as a secret source so secrets will be searched also in all the registered configuration sources.

## Installation
The environment variable secret provider is built-in as part of the package [Arcus.Security.Core](https://www.nuget.org/packages/Arcus.Security.Core).

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