---
title: "Docker Secrets secret provider"
layout: default
---

# Docker Secrets secret provider
The _DockerSecrets_  secret provider allows working with Docker secrets.  When using Docker secrets in Docker Swarm, the secrets are injected in the Docker container as files.  
The _DockerSecrets_ secret provider provides access to those secrets via the secret store.

This secret provider offers functionality which is equivalent to the _KeyPerFile_ Configuration Provider, but instead of adding the secrets to the Configuration, this secret provider allows access to the Docker Secrets via the _ISecretProvider_ interface.

## Installation
Adding secrets from the User Secrets manager into the secret store requires following package:

```shell
PM > Install-Package Arcus.Security.Providers.DockerSecrets
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
                        // Adds the secrets that exist in the "/run/secrets" directory to the ISecretStore
                        // Docker secrets are by default mounted into the /run/secrets directory
                        // when using Linux containers on Docker Swarm.
                        builder.AddDockerSecrets(directoryPath: "/run/secrets");
                    })
                    .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

## Retrieving secrets

Suppose you have the following docker-compose file:

```yaml
version: '3.8'
services:
  person-api:
    image: person-api:latest
    ports:
        - 5555:80
    secrets:
        - ConnectionStrings__PersonDatabase

secrets:
  ConnectionStrings__PersonDatabase:
    external: true
```

After adding the _DockerSecrets_ secret provider to the secret store, the Docker secrets can simply be retrieved by calling the appropriate methods on the `ISecretProvider`:

```csharp
public class PersonController
{
    private readonly ISecretProvider _secrets;

    public PersonController(ISecretProvider secrets)
    {
        _secrets = secrets;
    }

    [HttpGet]
    public async Task GetPerson(Guid personId)
    {
        string connectionstring = await _secrets.GetRawSecretAsync("ConnectionStrings:PersonDatabase")

        using (var connection = new SqlDbConnection(connectionstring))
        {
            var person = new PersonRepository(connection).GetPersonById(personId);
            return Ok(new { Id = person.Id, Name = person.Name });
        }
    }
}
```

[&larr; back](/)
