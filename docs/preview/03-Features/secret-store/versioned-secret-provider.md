---
title: "Secret versions"
layout: default
---

# Adding secret versions to secret store
The basic functionality of the Arcus secret store is one-way secret retrieval, meaning that a single secret matches a single secret name. 
In production scenario's, multiple versions of a secrets are possible especially in key rotation scenario's where you would want to support the 'older' version until each system uses the new one.

In those scenario's, the secret provider implementations registered in the secret store should be able to return many secret values based on a secret name.
Currently, only the Azure Key Vault secret provider is adapted to use many secret versions, but nothing stops you from implementing your own versioned secret provider.

## Example: Azure Key Vault secret versions
The following example will show you how two secret versions are taken into account when retrieving a secret from the secret store.
Any secret retrievals for `MySecret` will make sure that the Azure Key Vault implementation takes the latest two secret versions.

```csharp
using Arcus.Security.Core.Caching.Configuration;
using Microsoft.Extensions.Hosting;

public class Program
{
    public static void Main(string[] args)
    {
        Host.CreateDefaultBuilder()
            .ConfigureSecretStore((configuration, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(..., (SecretProviderOptions options) =>
                {
                    options.AddVersionedSecret("MySecret", allowedVersions: 2);
                });
            })
            .Build()
            .Run();
	}
}
```

This secret version registration also poses the question of how these two versions of the secret can be used, since the basic secret store interface only provides single secrets.
Additional extensions are added on the secret store that allows you to interact with the available secret versions in your application:
```csharp
using Arcus.Security.Core;

[ApiController]
[Route("/api/v1/order")]
public class OrderController : ControllerBase
{
    private readonly ISecretProvider _secretProvider;

    public OrderController(ISecretProvider secretProvider)
    {
        _secretProvider = secretProvider;
    }

    [HttpPost]
    public async Task<IActionResult> Post([FromBody] Order order)
    {
        // Get all secrets available.
        IEnumeration<Secret> secrets = await _secretProvider.GetSecretsAsync("MySecret");

        // Get all secret values available.
        IEnumeration<string> secretValues = await _secretProvider.GetRawSecretsAsync("MySecret");
    }
}
```

> Note that since we only allowed 2 secret versions in the registration, the Azure Key Vault will only return two secrets. If there more registered versions allowed than available on Azure Key Vault, then the maximum amount available will return

> 💡 Note that versioned secrets can be combined with caching. The set of secrets will be cached, just like a single secret.
