using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Providers.HashiCorp.Extensions;
using Arcus.Security.Tests.Unit.HashiCorp.Fixture;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using VaultSharp;
using VaultSharp.V1.AuthMethods.UserPass;
using Xunit;

namespace Arcus.Security.Tests.Unit.HashiCorp
{
    public class SecretStoreBuilderExtensionsTests
    {
        public static IEnumerable<object[]> OutOfBoundsClientApiVersion => new[]
        {
            new object[] { (VaultKeyValueSecretEngineVersion) 5 },
            new object[] { VaultKeyValueSecretEngineVersion.V1 | VaultKeyValueSecretEngineVersion.V2 },
        };

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpVault_WithoutUsername_Throws(string userName)
        {
            // Arrange
            var builder = new HostBuilder();
            var password = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass("https://vault.uri:456", userName, password, secretPath: "secret/path");
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpVault_WithoutPassword_Throws(string password)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass("https://vault.uri:456", userName, password, secretPath: "secret/path");
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpVault_WithAdditionalOptionsWithoutUsername_Throws(string userName)
        {
            // Arrange
            var builder = new HostBuilder();
            var password = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass("https://vault.uri:456", userName, password, secretPath: "secret/path", configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpVault_WithAdditionalOptionsWithoutPassword_Throws(string password)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass("https://vault.uri:456", userName, password, secretPath: "secret/path", configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpVault_WithoutJwt_Throws(string jwt)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithKubernetes("https://vault.uri:456", "role name", jwt, "secret/path");
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpVaultWithKubernetes_WithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithKubernetes(vaultUri, "role name", "jwt", "secret/path");
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpVault_WithAdditionalOptionsWithoutJwt_Throws(string jwt)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithKubernetes("https://vault.uri:456", "role name", jwt, "secret/path", configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpVaultWithKubernetes_WithAdditionalOptionsWithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithKubernetes(vaultUri, "role name", "jwt", "secret/path", configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpVaultWithUserPass_WithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass(vaultUri, userName, password, "secret/path");
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpVaultWithUserPass_WithAdditionalOptionsWithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass(vaultUri, userName, password, "secret/path", configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpWithKubernetes_WithoutSecretPath_Throws(string secretPath)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithKubernetes("https://vault.uri:456", "role name", "jwt", secretPath);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpWithKubernetes_WithAdditionalOptionsWithoutSecretPath_Throws(string secretPath)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithKubernetes("https://vault.uri:456", "role name", "jwt", secretPath, configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpWithUserPass_WithoutSecretPath_Throws(string secretPath)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass("https://vault.uri:456", userName, password, secretPath);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpWithUserPass_WithAdditionalOptionsWithoutSecretPath_Throws(string secretPath)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass("https://vault.uri:456", userName, password, secretPath, configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [MemberData(nameof(OutOfBoundsClientApiVersion))]
        public void AddHashiCorpWithKubernetes_WithOutOfBoundsKeyValueVersion_Throws(VaultKeyValueSecretEngineVersion secretEngineVersion)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithKubernetes(
                    vaultServerUriWithPort: "https://vault.uri:456", 
                    roleName: "role name", 
                    jsonWebToken: "jwt", 
                    secretPath: "secret/path", 
                    configureOptions: options => options.KeyValueVersion = secretEngineVersion,
                    name: null,
                    mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [MemberData(nameof(OutOfBoundsClientApiVersion))]
        public void AddHashiCorpWithUserPass_WithOutOfBoundsKeyValueVersion_Throws(VaultKeyValueSecretEngineVersion secretEngineVersion)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass("https://vault.uri:456", userName, password, "secret/path", options => options.KeyValueVersion = secretEngineVersion);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [MemberData(nameof(OutOfBoundsClientApiVersion))]
        public void AddHashiCorp_WithOutOfBoundsKeyValueVersion_Throws(VaultKeyValueSecretEngineVersion secretEngineVersion)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();
            var settings = new VaultClientSettings("https://vault.uri:456", new UserPassAuthMethodInfo(userName, password));

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault(
                    settings: settings, 
                    secretPath: "secret/path", 
                    configureOptions: options => options.KeyValueVersion = secretEngineVersion,
                    name: null,
                    mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddHashiCorp_WithoutSettings_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault(settings: null, secretPath: "secret/path");
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddHashiCorp_WithAdditionalOptionsWithoutSettings_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault(settings: null, secretPath: "secret/path", configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorp_WithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();
            var settings = new VaultClientSettings(vaultUri, new UserPassAuthMethodInfo(userName, password));

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault(settings, secretPath: "secret/path");
            });

            // Assert
            var exception = Assert.ThrowsAny<Exception>(() => builder.Build());
            Assert.True(exception is ArgumentException || exception is UriFormatException);
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorp_WithAdditionalOptionsWithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();
            var settings = new VaultClientSettings(vaultUri, new UserPassAuthMethodInfo(userName, password));

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault(settings, secretPath: "secret/path", configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            var exception = Assert.ThrowsAny<Exception>(() => builder.Build());
            Assert.True(exception is ArgumentException || exception is UriFormatException);
        }

        [Fact]
        public void AddHashiCorp_WithoutAuthenticationMethod_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var settings = new VaultClientSettings("https://vault.uri:456", authMethodInfo: null);

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault(settings, secretPath: "secret/path");
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddHashiCorp_WithAdditionalOptionsWithoutAuthenticationMethod_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var settings = new VaultClientSettings("https://vault.uri:456", authMethodInfo: null);

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault(settings, secretPath: "secret/path", configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpWithUserPass_WithoutUserPassAuthenticationMountPoint_Throws(string userPassMountPoint)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass(
                    "https://vault.uri:456",
                    userName,
                    password,
                    "secret/path",
                    options =>
                    {
                        options.KeyValueVersion = VaultKeyValueSecretEngineVersion.V2;
                        options.UserPassMountPoint = userPassMountPoint;
                    });
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpWithKubernetes_WithoutKubernetesAuthenticationMountPoint_Throws(string kubernetesMountPoint)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithKubernetes(
                    vaultServerUriWithPort: "https://vault.uri:456",
                    roleName: "rolename",
                    jsonWebToken: "jwt",
                    secretPath: "secret/path",
                    configureOptions: options =>
                    {
                        options.KeyValueVersion = VaultKeyValueSecretEngineVersion.V2;
                        options.KubernetesMountPoint = kubernetesMountPoint;
                    },
                    name: null,
                    mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpWithUserPass_WithoutKeyValueMountPoint_Throws(string keyValueMountPoint)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithUserPass(
                    "https://vault.uri:456",
                    userName,
                    password,
                    "secret/path",
                    options =>
                    {
                        options.KeyValueVersion = VaultKeyValueSecretEngineVersion.V2;
                        options.KeyValueMountPoint = keyValueMountPoint;
                    });
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorpWithKubernetes_WithoutKeyValueMountPoint_Throws(string keyValueMountPoint)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVaultWithKubernetes(
                    vaultServerUriWithPort: "https://vault.uri:456",
                    roleName: "rolename",
                    jsonWebToken: "jwt",
                    secretPath: "secret/path",
                    configureOptions: options =>
                    {
                        options.KeyValueVersion = VaultKeyValueSecretEngineVersion.V2;
                        options.KeyValueMountPoint = keyValueMountPoint;
                    },
                    name: null,
                    mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddHashiCorp_WithoutKeyValueMountPoint_Throws(string keyValueMountPoint)
        {
            // Arrange
            var builder = new HostBuilder();
            var userName = Guid.NewGuid().ToString();
            var password = Guid.NewGuid().ToString();
            var settings = new VaultClientSettings("https://vault.uri:456", new UserPassAuthMethodInfo(userName, password));

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault(
                    settings: settings,
                    secretPath: "secret/path",
                    configureOptions: options =>
                    {
                        options.KeyValueVersion = VaultKeyValueSecretEngineVersion.V2;
                        options.KeyValueMountPoint = keyValueMountPoint;
                    },
                    name: null,
                    mutateSecretName: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public async Task AddHashiCorpT_WithCustomImplementation_Succeeds()
        {
            // Arrange
            var builder = new HostBuilder();
            var expected = $"secret-{Guid.NewGuid()}";
            
            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault(serviceProvider => new SingleValueHashiCorpSecretProvider(expected));
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var secretProvider = host.Services.GetRequiredService<ISecretProvider>();
                string actual = await secretProvider.GetRawSecretAsync("MySecret");
                Assert.Equal(expected, actual);
            }
        }
        
        [Fact]
        public void AddHashiCorpTWithNameAndSecretNameMutation_WithoutImplementationFactory_Fails()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault<SingleValueHashiCorpSecretProvider>(
                    implementationFactory: null,
                    name: "HashiCorp",
                    mutateSecretName: name => name);
            });
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddHashiCorpT_WithoutImplementationFactory_Fails()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddHashiCorpVault<SingleValueHashiCorpSecretProvider>(implementationFactory: null);
            });
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
    }
}
