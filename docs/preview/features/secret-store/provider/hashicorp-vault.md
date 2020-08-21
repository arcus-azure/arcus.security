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
                        builder.AddHashiCorpVaultWithUserPass(..., userPassMountPoint: "myuserpass");

                         // Version of the KeyValue secret engine (default: V2).
                         builder.AddHashiCorpVaultWithUserPass(..., keyValueVersion: VaultKeyValueSecretEngineVersion.V1);

                        // Mount point of KeyValue secret engine (default: kv-v2).
                        builder.AddHashiCorpVaultWithUserPass(..., keyValueMountPoint: "secret");

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
                        builder.AddHashiCorpVaultWithKubernetes(..., kubernetesMountPoint: "mykubernetes");

                         // Version of the KeyValue secret engine (default: V2).
                         builder.AddHashiCorpVaultWithKubernetes(..., keyValueVersion: VaultKeyValueSecretEngineVersion.V1);

                        // Mount point of KeyValue secret engine (default: kv-v2).
                        builder.AddHashiCorpVaultWithKubernetes(..., keyValueMountPoint: "secret");

                        // Custom settings overload for when using the [VaultSharp](https://github.com/rajanadar/VaultSharp) settings directly.
                        // -------------------------
                        var tokenAuthentication = new TokenAuthMethodInfo("token");
                        var settings = VaultClientSettings("http://uri.to.your.running.vault.5200", tokenAuthentication);
                        builder.AddHashiCorpVault(
                            settings, 
                            // Path where the secrets are stored in the KeyValue secret engine.
                            secretPath: "my-secrets");

                        // Version of the KeyValue secret engine (default: V2).
                         builder.AddHashiCorpVault(..., keyValueVersion: VaultKeyValueSecretEngineVersion.V1);

                        // Mount point of KeyValue secret engine (default: kv-v2).
                        builder.AddHashiCorpVault(..., keyValueMountPoint: "secret");
                    })
                    .ConfigureWebHostDefaults(webBuilder => webBuilder.UseStartup<Startup>());
    }
}
```

[&larr; back](/)
