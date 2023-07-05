---
title: "Dapr secret provider"
layout: default
---

# Dapr secret provider
Dapr secret provider brings secrets from the Dapr secret store to your application. Dapr is commonly used in Kubernetes environments where there is usually not the same network capabilities as other application environments.
By using this secret provider, you still benefit from all the Arcus secret store features, while still using Dapr as your external secret source.

⛔ Does not support [synchronous secret retrieval](../../secrets/general.md).

## Installation
Adding secrets from Dapr into the secret store requires following package:

```shell
PM > Install-Package Arcus.Security.Providers.Dapr
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
        return Host.CreateDefaultBuilder(args).ConfigureSecretStore((context, config, builder) =>
        {
              // Adding the Dapr secret provider with the built-in overloads.
              builder.AddDaprSecretStore(
                  // Name of the secret store where Dapr gets its secrets.
                  secretStore: "mycustomsecretstore",
                  // Following defaults can be overridden:
                  configureOptions: options =>
                  {
                     // The URI endpoint to use for gRPC calls to the Dapr runtime.
                     //      The default value will be http://127.0.0.1:DAPR_GRPC_PORT where DAPR_GRPC_PORT represents the value of the DAPR_GRPC_PORT environment variable.
                     options.GrpcEndpoint = "http://127.0.0.1:5001/";
        
                     // The URI endpoint to use for HTTP calls to the Dapr runtime.
                     //      The default value will be http://127.0.0.1:DAPR_HTTP_PORT where DAPR_HTTP_PORT represents the value of the DAPR_HTTP_PORT environment variable.
                     options.HttpEndpoint = "http://127.0.0.1:5002";
        
                     // The API token on every request to the Dapr runtime (added to the request's headers).
                     options.DaprApiToken = "my-api-key";
        
                     // Tracking the Dapr secret store dependency which works well together with Application Insights (default: `false`).
                     //      See https://observability.arcus-azure.net/features/writing-different-telemetry-types#measuring-custom-dependencies for more information.
                     options.TrackDependency = true;

                     // Additional metadata entry which will be sent to the Dapr secret store on every request.
                     options.AddMetadata("my-dapr-key", "my-dapr-value");
                  });
        });
    }
}
```

### Custom implementation
We allow custom implementations of the Dapr secret provider.
This can come in handy when you want to perform additional actions during the secret retrieval.

**Example**
In this example we'll create a custom implementation for the local Dapr secret store that allows multi-valued secrets.
First, we'll implement the `DaprSecretProvider`:

```csharp
using Arcus.Security.Providers.Dapr;

public class MultiValuedLocalDaprSecretProvider : DaprSecretProvider
{
    public MultiValuedLocalDaprSecretProvider(
        string secretStore, 
        DaprSecretProviderOptions options, 
        ILogger<DaprSecretProvider> logger) : base(secretStore, options, logger)
    {
    }
}
```

👀 Notice that we require to take in the name of the Dapr secret store and the additional user-defined options which can be configured during the registration of the secret provider.

To control how Dapr secrets be retrieved, we need to implement the `DetermineDaprSecretName` method which takes in the secret name like it comes into the secret provider, and implement the multi-valued implementation:

```csharp
using Arcus.Security.Providers.Dapr;

public class MultiValuedLocalDaprSecretProvider : DaprSecretProvider
{
    // Constructor truncated...

    /// <summary>
    /// Determine the Dapr secret key and section based on the user passed-in <paramref name="secretName"/>.
    /// </summary>
    /// <remarks>
    ///     The key of the secret in the Dapr secret store can be the same as the section for single-valued Dapr secrets, but is different in multi-valued Dapr secrets.
    ///     Therefore, make sure to split the <paramref name="secretName"/> into the required (key, section) pair for your use-case.
    /// </remarks>
    /// <param name="secretName">The user passed-in secret which gets translated to a Dapr secret key and section.</param>
    protected override (string daprSecretKey, string daprSecretSection) DetermineDaprSecretName(string secretName)
    {
        const string nestedSeparator = ":";
    
        string[] subKeys = secretName.Split(nestedSeparator, StringSplitOptions.RemoveEmptyEntries);
        if (subKeys.Length >= 2)
        {
            string remaining = string.Join(nestedSeparator, subKeys.Skip(1));
            return (subKeys[0], remaining);
        }
    
        return (secretName, secretName);
    }
}
```

> 💡 Dapr allows for multi-valued secrets for the local Dapr secret store. This means that while single-valued secrets have the same 'key' as 'section' in the returned dictionary, multi-valued secrets are retrieved differently. For more information on the Dapr .NET SDK, see [their official documentation](https://docs.dapr.io/developing-applications/sdks/dotnet/).

Such a custom implementation can easily be registered with a dedicated extension on the secret store:

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
        return Host.CreateDefaultBuilder(args).ConfigureSecretStore((config, context, stores) =>
        {
            stores.AddDaprSecretStore(
                (IServiceProvider provider, DaprSecretProviderOptions options) =>
                {
                    var logger = provider.GetService<ILogger<DaprSecretProvider>>();
                    return new MultiValuedLocalDaprSecretProvider("mycustomsecretstore", options, logger);
                },
                (DaprSecretProviderOptions options) => 
                { 
                    // Configure additional options which can be passed in the implementation factory function of the custom implementation.
                });
        });
    }
}
```