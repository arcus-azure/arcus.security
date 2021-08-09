---
title: "Command line secret provider"
layout: default
---

# Command line secret provider
The command line secret provider transforms all your command line arguments in application secrets.

## Installation
Adding command line arguments into the secret store requires following package:

```shell
PM > Install-Package Arcus.Security.Providers.CommandLine
```

## Configuration
After installing the package, the addtional extensions becomes available when building the secret store.

```csharp
using Arcus.Security.Core;
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
                       // Uses the passed-in command line arguments as secrets in the secret store.
                       builder.AddCommandLine(args);

                       // Uses the passed-in command lien arguments, using underscores and capitals for secret name structure.
                       // Example - When looking up Queue.Name it will be changed to ARCUS_QUEUE_NAME.
                       builder.AddCommandLine(args, mutateSecretName: secretName => secretName.Replace(".", "_").ToUppder());

                       // Providing an unique name to this secret provider so it can be looked up later.
                       // See: "Retrieve a specific secret provider from the secret store"
                       builder.AddCommandLine(args, name: "CommandLine");
                    })
                    .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```
