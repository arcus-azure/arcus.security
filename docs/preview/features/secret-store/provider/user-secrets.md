---
title: "User Secrets secret provider"
layout: default
---

# User Secrets manager secret provider
User Secrets secret provider brings local secrets during development to your application.

> :warning: When using User Secrets secret provider, it will look for secrets on the local disk which is not secure. This provider should only be used for development.

## Installation
Adding secrets from the User Secrets manager into the secret store requires following package:

```shell
PM > Install-Package Arcus.Security.Providers.UserSecrets
```

## Configuration
After installing the package, the addtional extensions becomes available when building the secret store.

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
                   .ConfigureSecretStore((context, config, builder) =>
                   {
                         // Adds the user secrets configuration source with specified user secrets ID.
                         // A user secrets ID is unique value used to store and identify a collection of secrets.

                         // `Progam`: The type from the assembly to search for an instance of `UserSecretsIdAttribute`.
                         builder.AddUserSecrets<Program>();

                         // The user secrets ID which gets provided directly without looking up the `UserSecretsIdAttribute` in the assembly.
                         builder.AddUserSecrets("bee01c693fe44766b1f3ef1e1f1f7883");
                    })
                    .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

[&larr; back](/)
