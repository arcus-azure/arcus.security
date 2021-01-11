---
title: "Environment variables secret provider"
layout: default
---

# Environment variables secret provider
Environment variable secret provider brings environment variables as secrets to your application.

## Installation
The environment variable secret provider is built-in as part of the package [Arcus.Security.Core](https://www.nuget.org/packages/Arcus.Security.Core).

## Configuration
The secret provider is available as an extension.

```csharp
using Microsoft.Extensions.Hosting;

public class Program
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args)
    {    
        return Host.CreateDefaultBuilder(args)
                   .ConfigureSecretStore((context, config, builder) =>
                   {
                       builder.AddEnvironmentVariables();
                   })
                   .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```
