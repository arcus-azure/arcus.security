---
title: "User Secrets"
---

# User Secrets manager secret provider
User Secrets secret provider brings local secrets during development to your application.

:::warning[only for development]
When using User Secrets secret provider, it will look for secrets on the local disk, which is not secure. This provider **SHOULD ONLY** be used for development.
:::

## Installation
Adding secrets from the User Secrets manager into the secret store requires following package:

```powershell
PM > Install-Package Arcus.Security.Providers.UserSecrets
```

## Configuration
After installing the package, the additional extensions becomes available when building the secret store.

```csharp
var builder = Host.CreateDefaultBuilder(args);
builder.ConfigureSecretStore((_, store) =>
{
    // Adds the user secrets secret source with specified user secrets ID.
    // A user secrets ID is a unique value used to store and identify a collection of secrets.

    // `Program`: The type from the assembly to search for an instance of `UserSecretsIdAttribute`.
    store.AddUserSecrets<Program>();
    store.AddUserSecrets(typeof(Program).GetTypeInfo().Assembly);

    // The user secrets ID which gets provided directly without looking up the `UserSecretsIdAttribute` in the assembly.
    store.AddUserSecrets("bee01c693fe44766b1f3ef1e1f1f7883");
});
```

