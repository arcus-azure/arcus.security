---
title: "Command line"
---

# Command line secret provider
The command line secret provider transforms all your command line arguments in application secrets.

## Installation
Adding command line arguments into the secret store requires following package:

```powershell
PM > Install-Package Arcus.Security.Providers.CommandLine
```

## Configuration
After installing the package, the additional extensions becomes available when building the secret store.

```csharp
var builder = Host.CreateDefaultBuilder(args);
builder.ConfigureSecretStore((_, store) =>
{
    store.AddCommandLine(args);
});
```
