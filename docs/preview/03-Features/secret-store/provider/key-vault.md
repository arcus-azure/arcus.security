---
title: "Azure Key Vault"
---

# Azure Key Vault secret provider
Azure Key Vault secret provider brings secrets from Azure Key Vault to your application.

## Installation
Adding secrets from Azure Key Vault into the secret store requires following package:

```powershell
PM > Install-Package Arcus.Security.Providers.AzureKeyVault
```

## Configuration
After installing the package, the additional extensions becomes available when building the secret store.

```csharp
var builder = Host.CreateDefaultBuilder(args);
builder.ConfigureSecretStore((_, store) =>
{
    // #1 Using token credentials.
    store.AddAzureKeyVault("https://myvault.vault.azure.net", new ManagedIdentityCredential());

    // #2 Using already registered secret client.
    store.AddAzureKeyVault((IServiceProvider provider) =>
    {
        return provider.GetRequiredService<SecretClient>();
    })
});

builder.ConfigureServices(services =>
{
    services.AddAzureClients(clients =>
    {
        clients.AddSecretClient(new Uri("https://myvault.vault.azure.net"));
        clients.UseCredential(new ManagedIdentityCredential());
    })
});
```

