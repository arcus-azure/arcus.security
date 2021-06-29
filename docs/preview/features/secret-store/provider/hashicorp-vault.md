---
title: "HashiCorp Vault secret provider"
layout: default
---

# HashiCorp Vault secret provider
HashiCorp Vault secret provider brings secrets from the KeyValue secret engine to your application.

## Installation
Adding secrets from HashiCorp Vault into the secret store requires following package:

```shell
PM > Install-Package Arcus.Security.Providers.HashiCorp
```

## Configuration
After installing the package, the addtional extensions becomes available when building the secret store.

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
                         // Adding the HashiCorp Vault secret provider with the built-in overloads.
                         // =======================================================================
                         
                         // UserPass authentication built-in overload:
                         // ------------------------------------------
                         builder.AddHashiCorpVaultWithUserPass(
                             // URI where the HashiCorp Vault is running.
                             vaultServerUriWithPort: "https://uri.to.your.running.vault:5200",
                             // Username/Password combination to authenticate with the vault.
                             username: "admin",
                             password: "s3cr3t",
                             // Path where the secrets are stored in the KeyValue secret engine.
                             secretPath: "my-secrets"
                         );

                         // Following defaults can be overridden:

                        // Mount point of UserPass athentication (default: userpass).
                        builder.AddHashiCorpVaultWithUserPass(..., options => options.UserPassMountPoint: "myuserpass");

                         // Version of the KeyValue secret engine (default: V2).
                         builder.AddHashiCorpVaultWithUserPass(..., options => options.KeyValueVersion: VaultKeyValueSecretEngineVersion.V1);

                        // Mount point of KeyValue secret engine (default: kv-v2).
                        builder.AddHashiCorpVaultWithUserPass(..., options => options.KeyValueMountPoint: "secret");

                        // Adding the HashiCorp Vault secret provider with UserPass authentication, using `-` instead of `:` when looking up secrets.
                        // Example - When looking up `Foo:Bar` it will be changed to `Foo-Bar`.
                        builder.AddHashiCorpVaultWithUserPass(..., mutateSecretName: secretName => secretName.Replace(":", "-"));

                        // Providing an unique name to this secret provider so it can be looked up later.
                        // See: "Retrieve a specific secret provider from the secret store"
                        builder.AddHashiCorpVault(..., name: "HashiCorp"); 

                        // Kubernetes authentication built-in overload:
                        // --------------------------------------------
                        builder.AddHashiCorpVaultWithKubernetes(
                            // URI where the HashiCorp Vault is running.
                             vaultServerUriWithPort: "https://uri.to.your.running.vault:5200",
                             // Role name of the Kubernetes service account.
                             roleName: "admin",
                             // JSON web token (JWT) of the Kubernetes service account,
                             jwt: "ey.xxx.xxx",
                            // Path where the secrets are stored in the KeyValue secret engine.
                             secretPath: "my-secrets"
                        );

                        // Mount point of Kubernetes authentication (default: kubernetes).
                        builder.AddHashiCorpVaultWithKubernetes(..., options => options.KubernetesMountPoint: "mykubernetes");

                         // Version of the KeyValue secret engine (default: V2).
                         builder.AddHashiCorpVaultWithKubernetes(..., options => options.KeyValueVersion: VaultKeyValueSecretEngineVersion.V1);

                        // Mount point of KeyValue secret engine (default: kv-v2).
                        builder.AddHashiCorpVaultWithKubernetes(..., options => options.KeyValueMountPoint: "secret");

                        // Adding the HashiCorp Vault secret provider with Kubernetes authentication, using `-` instead of `:` when looking up secrets.
                        // Example - When looking up `Foo:Bar` it will be changed to `Foo-Bar`.
                        builder.AddHashiCorpVaultWithKubernetes(..., mutateSecretname: secretName => secretName.Replace(":", "-"));

                        // Providing an unique name to this secret provider so it can be looked up later.
                        // See: "Retrieve a specific secret provider from the secret store"
                        builder.AddHashiCorpVault(..., name: "HashiCorp"); 

                        // Custom settings overload for when using the [VaultSharp](https://github.com/rajanadar/VaultSharp) settings directly:
                        // --------------------------------------------------------------------------------------------------------------------
                        var tokenAuthentication = new TokenAuthMethodInfo("token");
                        var settings = VaultClientSettings("http://uri.to.your.running.vault.5200", tokenAuthentication);
                        builder.AddHashiCorpVault(
                            settings, 
                            // Path where the secrets are stored in the KeyValue secret engine.
                            secretPath: "my-secrets");

                        // Version of the KeyValue secret engine (default: V2).
                         builder.AddHashiCorpVault(..., options => options.KeyValueVersion: VaultKeyValueSecretEngineVersion.V1);

                        // Mount point of KeyValue secret engine (default: kv-v2).
                        builder.AddHashiCorpVault(..., options => options.KeyValueMountPoint: "secret");

                        // Adding the HashiCorp Vault secret provider, using `-` instead of `:` when looking up secrets.
                        // Example - When looking up `Foo:Bar` it will be changed to `Foo-Bar`.
                        builder.AddHashiCorpVault(..., mutateSecretName: secretName => secretName.Replace(":", "-"));

                        // Providing an unique name to this secret provider so it can be looked up later.
                        // See: "Retrieve a specific secret provider from the secret store"
                        builder.AddHashiCorpVault(..., name: "HashiCorp");

                        // Additional settings:
                        // -------------------

                        // Tracking the HashiCorp Vault dependency which works well together with Application Insights (default: `false`).
                        // See https://observability.arcus-azure.net/features/writing-different-telemetry-types#measuring-custom-dependencies for more information.
                        builder.AddHashiCorpVault(..., options => options.TrackDependency = true);
                    })
                    .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

### Custom implementation
We allow custom implementations of the HashiCorp Vault secret provider. 
This can come in handy when you want to perform additional actions during the secret retrieval or want to extend the available HashiCorp Vault authentication options.

In this example we'll add retry functionality, using [Polly](https://github.com/App-vNext/Polly), to the secret provider.
First, you'll have to implement the `HashiCorpSecretProvider`.

```csharp
using Polly;
using Polly.Retry;

public class RetryableHashiCorpSecretProvider : HashiCorpSecretProvider
{
    private readonly AsyncRetryPolicy _retryPolicy;

    public RetryableHashiCorpSecretProvider(
        VaultClientSettings settings,
        string secretPath,
        HashiCorpVaultOptions options,
        AsyncRetryPolicy retryPolicy,
        ILogger<HashiCorpSecretProvider> logger)
        : base(settings, secretPath, options, logger)
    {
        _retryPolicy = rectryPolicy;
    }

    public override async Task<Secret> GetSecretAsync(string secretName)
    {
        await _retryPolicy.ExecuteAsync(async () => 
        {
            await base.GetSecretAsync(secretName);
        });
    }

    public override async Task<string> GetRawSecretAsync(string secretName)
    {
        await _retryPolicy.ExecuteAsync(async () => 
        {
            await base.GetRawSecretAsync(secretName);
        });
    }
}
```

As you can see, we allo both secret retrieval methods to be overwritten so we can prepend our retryable functionality.
To use this within the secret store, you can use the available method extension that allows you to provide your custom implementation type:

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
                   .ConfigureSecretStore((context, config, stores) =>
                   {
                        stores.AddHashiCorp<RetryableHashiCorpSecretProvider>((IServiceProvider serviceProvider) =>
                        {
                            // UserPass authentication options.
                            var options = new HashiCorpVaultUserPassOptions();
                            var authenticationMethod = new UserPassAuthMethodInfo(options.UserPassMountPoint, "admin"", "P@ssw0rd");
                            var settings = new VaultClientSettings("https://uri.to.your.running.vault:5200", authenticationMethod);
                            var logger = serviceProvider.GetService<ILogger<RetryableHashiCorpSecretProvider>>();

                            // Retryable options.
                            var retryPolicy =
                                Policy.Handle(exceptionPredicate)
                                      .WaitAndRetryAsync(5, attempt => TimeSpan.FromSeconds(1));

                            return new RetryableHashiCorpSecretProvider(settings, "my-secrets-path", options, retryPolicy, logger);
                        });
                   });
    }
}
```
That's all it takes to use your custom implementation.

We also recommend to use a custom extension on the secret store builder to make this more user-friendly.

```csharp
public static class SecretStoreBuilderExtensions
{
    public static SecretStoreBuilder AddRetryableHashiCorpWithUserPass(
        this SecretStoreBuilder builder,
        string vaultServerUriWithPort,
        string username,
        string password,
        string secretPath,
        AsyncRetryPolicy retryPolicy,
        Action<HashiCorpVaultUserPassOptions> configureOptions)
    {
        builder.AddProvider<RetryableHashiCorpSecretProvider>((IServiceProvider serviceProvider) =>
        {
            var options = new HashiCorpVaultUserPassOptions();
            var authenticationMethod = new UserPassAuthMethodInfo(options.UserPassMountPoint, username, password);
            var settings = new VaultClientSettings(vaultServerUriWithPort, authenticationMethod);
            var logger = serviceProvider.GetService<ILogger<RetryableHashiCorpSecretProvider>>();

            return new RetryableHashiCorpSecretProvider(settings, secretPath, options, retryPolicy, logger);
        });
    }
}
```

[&larr; back](/)
