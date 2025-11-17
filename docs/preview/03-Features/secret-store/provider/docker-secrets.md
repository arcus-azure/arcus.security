---
title: "Docker Secrets"
---

# Docker Secrets secret provider
This provider allows you to work with Docker secrets. When using Docker secrets in Docker Swarm, the secrets are injected in the Docker container as files.  
The Docker secrets secret provider provides access to those secrets via the secret store.

This secret provider offers functionality which is equivalent to the _KeyPerFile_ Configuration Provider.

## Installation
Adding secrets from the User Secrets manager into the secret store requires following package:

```powershell
PM > Install-Package Arcus.Security.Providers.DockerSecrets
```

## Configuration
After installing the package, the additional extensions becomes available when building the secret store.

```csharp
var builder = Host.CreateDefaultBuilder(args);
builder.ConfigureSecretStore((_, store) =>
{
    // Adds the secrets that exist in the "/run/secrets" directory to the ISecretStore
    // Docker secrets are by default mounted into the /run/secrets directory
    // when using Linux containers on Docker Swarm.
    store.AddDockerSecrets(directoryPath: "/run/secrets");
});
```