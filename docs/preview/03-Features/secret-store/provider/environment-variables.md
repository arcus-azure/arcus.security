---
title: "Environment variables secret provider"
layout: default
---

# Environment variables secret provider
Environment variable secret provider brings environment variables as secrets to your application.

⚡ Supports [synchronous secret retrieval](../../secrets/general.md).

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
                       // Uses the environment variables from the environment block associated with the current process.
                       builder.AddEnvironmentVariables();

                       // Uses the environment variables stored or retrieved from the HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment key in the Windows operating system registry.
                       builder.AddEnvironmentVariables(EnvironmentVariableTarget.Machine);

                       // Uses the environment variables starting with 'ARCUS_' from the environment block associated with the current process.
                       builder.AddEnvironmentVariables(prefix: "ARCUS_");

                       // Uses the environment variables, using underscores and capitals for secret name structure.
                       // Example - When looking up Queue.Name it will be changed to ARCUS_QUEUE_NAME.
                       builder.AddEnvironmentVariables(mutateSecretName: name => $"ARCUS_{name.Replace(".", "_").ToUpper()}");

                       // Providing an unique name to this secret provider so it can be looked up later.
                       // See: "Retrieve a specific secret provider from the secret store"
                       builder.AddEnvironmentVariables(..., name: "Configuration");
                   })
                   .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```
