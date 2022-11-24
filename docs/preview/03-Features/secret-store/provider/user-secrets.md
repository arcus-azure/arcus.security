---
title: "User Secrets secret provider"
layout: default
---

# User Secrets manager secret provider
User Secrets secret provider brings local secrets during development to your application.

⚡ Supports [synchronous secret retrieval](../../secrets/general.md).

> ⚠ When using User Secrets secret provider, it will look for secrets on the local disk which is not secure. This provider should only be used for development.

## Installation
Adding secrets from the User Secrets manager into the secret store requires following package:

```shell
PM > Install-Package Arcus.Security.Providers.UserSecrets
```

## Configuration
After installing the package, the additional extensions becomes available when building the secret store.

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
                         // Adds the user secrets secret source with specified user secrets ID.
                         // A user secrets ID is a unique value used to store and identify a collection of secrets.

                         // `Program`: The type from the assembly to search for an instance of `UserSecretsIdAttribute`.
                         builder.AddUserSecrets<Program>();

                         // The user secrets ID which gets provided directly without looking up the `UserSecretsIdAttribute` in the assembly.
                         builder.AddUserSecrets("bee01c693fe44766b1f3ef1e1f1f7883");

                         // The user secrets ID, using lower case transformation before looking up secrets.
                         // Example - When looking up `Client.ID` it will be changed to `client.id`.
                         builder.AddUserSecrets<Program>(mutateSecretName: secretName => secretName.ToLower());

                         // Providing an unique name to this secret provider so it can be looked up later.
                         // See: "Retrieve a specific secret provider from the secret store"
                         builder.AddUserSecrets(..., name: "UserSecrets");
                    })
                    .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

