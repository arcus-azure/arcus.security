using System;
using System.Security.Cryptography.X509Certificates;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Azure.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault.Extensions
{
    public class SecretStoreBuilderExtensionsTests
    {
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificate_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", certificate));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificate_WithCachingWithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", certificate, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimple_WithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());
            
            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", certificate));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimpleCacheConfiguration_WithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());
            
            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", certificate, cacheConfiguration: CacheConfiguration.Default));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificate_WithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", clientId, certificate));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificate_WithCachingWithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", clientId, certificate, cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimple_WithoutClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());
            
            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), clientId, "tenant-id", certificate));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimpleCacheConfiguration_WithoutClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());
            
            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), clientId, "tenant-id", certificate, cacheConfiguration: CacheConfiguration.Default));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultWithCertificate_WithoutCertificate_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", "client-id", certificate: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultWithCertificate_WithCachingWithoutCertificate_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", "client-id", certificate: null, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimple_WithoutTenant_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());
            
            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), tenantId, "client-id", certificate));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimpleCacheConfiguration_WithoutTenant_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());
            
            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), tenantId, "client-id", certificate, cacheConfiguration: CacheConfiguration.Default));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", certificate, cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithCachingWithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", certificate, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", clientId, certificate, cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithCachingWithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", clientId, certificate, cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithoutCertificate_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", "client-id", certificate: null, cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithCachingWithoutCertificate_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", "client-id", certificate: null, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultWithCertificateSimple_WithoutCertificate_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", "client-id", certificate: null));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultWithCertificateSimpleCacheConfiguration_WithoutCertificate_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", "client-id", certificate: null, cacheConfiguration: CacheConfiguration.Default));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithBlankTenant_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), tenantId, "client-id", certificate, cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithCachingWithBlankTenant_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), tenantId, "client-id", certificate, cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(),
                    "tenant-id",
                    "client-id",
                    certificate,
                    configureOptions: options => options.TrackDependency = true,
                    name: "Azure Key Vault",
                    mutateSecretName: name => name.Replace(":", "."),
                    cacheConfiguration: CacheConfiguration.Default);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }
        
        [Fact]
        public void AddAzureKeyVaultWithCertificateWithCacheConfiguration_WithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = CacheConfiguration.Default;
            var certificate = new X509Certificate2(Array.Empty<byte>());

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(),
                    "tenant-id",
                    "client-id",
                    certificate,
                    cacheConfiguration,
                    configureOptions: options => options.TrackDependency = true,
                    name: "Azure Key Vault",
                    mutateSecretName: name => name.Replace(":", "."));
            });

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentitySimple_WithoutVaultUriWithoutClientId_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentitySimple_WithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, "client-id"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentitySimpleCacheConfiguration_WithoutVaultUriWithoutClientId_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentitySimpleCacheConfiguration_WithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, cacheConfiguration, "client-id"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentity_WithBlankVaultUriWithoutClientId_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentity_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, clientId: null, cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentity_WithCachingWithBlankVaultUriWithoutClientId_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentity_WithCachingWithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, cacheConfiguration: cacheConfiguration, clientId: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultWithManagedIdentity_WithValidArgumentsWithoutClientId_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) =>
                {
                    stores.AddAzureKeyVaultWithManagedIdentity(
                        GenerateVaultUri(),
                        cacheConfiguration: null,
                        configureOptions: options => options.TrackDependency = true,
                        name: "Azure Key Vault",
                        mutateSecretName: name => name.Replace(":", "."));
                });

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }
        
        [Fact]
        public void AddAzureKeyVaultWithManagedIdentity_WithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) =>
                {
                    stores.AddAzureKeyVaultWithManagedIdentity(
                        GenerateVaultUri(),
                        clientId: "client-id",
                        cacheConfiguration: null,
                        configureOptions: options => options.TrackDependency = true,
                        name: "Azure Key Vault",
                        mutateSecretName: name => name.Replace(":", "."));
                });

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }
        
        [Fact]
        public void AddAzureKeyVaultWithManagedIdentityWithCacheConfiguration_WithValidArgumentsWithoutClientId_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) =>
                {
                    stores.AddAzureKeyVaultWithManagedIdentity(
                        GenerateVaultUri(),
                        cacheConfiguration: cacheConfiguration,
                        configureOptions: options => options.TrackDependency = true,
                        name: "Azure Key Vault",
                        mutateSecretName: name => name.Replace(":", "."));
                });

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }
        
        [Fact]
        public void AddAzureKeyVaultWithManagedIdentityWithCacheConfiguration_WithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) =>
                {
                    stores.AddAzureKeyVaultWithManagedIdentity(
                        GenerateVaultUri(),
                        cacheConfiguration: cacheConfiguration,
                        clientId: "client-id",
                        configureOptions: options => options.TrackDependency = true,
                        name: "Azure Key Vault",
                        mutateSecretName: name => name.Replace(":", "."));
                });

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipal_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipal_WithCachingWithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret", cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimple_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimpleCacheConfiguration_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret", cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipal_WithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", clientId, "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipal_WithCachingWithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", clientId, "client-secret", cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimple_WithoutTenantId_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), tenantId, "client-id", "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimpleCacheConfiguration_WithoutTenantId_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), tenantId, "client-id", "client-secret", cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimple_WithoutClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", clientId, "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimpleCacheConfiguration_WithoutClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", clientId, "client-secret", cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipal_WithBlankClientSecret_Throws(string clientSecret)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", "client-id", clientSecret));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipal_WithCachingWithBlankClientSecret_Throws(string clientSecret)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", "client-id", clientSecret, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimple_WithoutClientKey_Throws(string clientKey)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", "client-id", clientKey));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimpleCacheConfiguration_WithoutClientKey_Throws(string clientKey)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", "client-id", clientKey, cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithTenant_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret", cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithTenant_WithCachingWithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret", cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithTenant_WithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", clientId, "client-secret", cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithTenant_WithCachingWithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", clientId, "client-secret", cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithTenant_WithBlankClientSecret_Throws(string clientSecret)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", "client-id", clientSecret, cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithTenant_WithCachingWithBlankClientSecret_Throws(string clientSecret)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", "client-id", clientSecret, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithTenant_WithCachingWithBlankTenant_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), tenantId, "client-id", "client-secret", cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithTenant_WithBlankTenant_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), tenantId, "client-id", "client-secret", cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultWithServicePrincipalWithTenant_WithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) =>
                {
                    stores.AddAzureKeyVaultWithServicePrincipal(
                        GenerateVaultUri(),
                        "tenant-id",
                        "client-id",
                        "client-secret",
                        configureOptions: options => options.TrackDependency = true,
                        name: "Azure Key Vault",
                        mutateSecretName: name => name.Replace(":", "."),
                        cacheConfiguration: CacheConfiguration.Default);
                });

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }
        
        [Fact]
        public void AddAzureKeyVaultWithServicePrincipalWithCacheConfiguration_WithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore(
                (_, stores) =>
                {
                    stores.AddAzureKeyVaultWithServicePrincipal(
                        GenerateVaultUri(),
                        "tenant-id",
                        "client-id",
                        "client-secret",
                        configureOptions: options => options.TrackDependency = true,
                        name: "Azure Key Vault",
                        mutateSecretName: name => name.Replace(":", "."),
                        cacheConfiguration: cacheConfiguration);
                });

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }

        [Fact]
        public void AddAzureKeyVaultSdkSimple_WithoutVaultConfiguration_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var credential = Mock.Of<TokenCredential>();
            
            // Act
            builder.ConfigureSecretStore((_, stores) =>
                stores.AddAzureKeyVault(tokenCredential: credential, cacheConfiguration: null, configuration: null));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultSdk_WithoutVaultConfiguration_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var credential = Mock.Of<TokenCredential>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVault(credential, configuration: null, cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultSdkSimple_WithoutTokenCredential_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var configuration = Mock.Of<IKeyVaultConfiguration>();
            
            // Act
            builder.ConfigureSecretStore((_, stores) =>
                stores.AddAzureKeyVault(tokenCredential: null, configuration: configuration));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultSdkSimpleCacheConfiguration_WithoutVaultConfiguration_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var credential = Mock.Of<TokenCredential>();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVault(credential, configuration: null, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultSdk_WithCachingWithoutVaultConfiguration_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var credential = Mock.Of<TokenCredential>();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVault(credential, configuration: null, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultSdk_WithoutTokenCredential_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var configuration = Mock.Of<IKeyVaultConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVault(tokenCredential: null, configuration: configuration, cacheConfiguration: null, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultSdk_WithCachingWithoutTokenCredential_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var configuration = Mock.Of<IKeyVaultConfiguration>();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVault(tokenCredential: null, configuration: configuration, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultSdkSimpleCacheConfiguration_WithoutTokenCredential_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var configuration = Mock.Of<IKeyVaultConfiguration>();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (_, stores) => stores.AddAzureKeyVault(tokenCredential: null, configuration: configuration, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultSdkSimple_WithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            var credential = Mock.Of<TokenCredential>();
            var configuration = new KeyVaultConfiguration(GenerateVaultUri());
            
            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVault(credential, configuration));

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }
        
        [Fact]
        public void AddAzureKeyVaultSdkSimpleCacheConfiguration_WithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            var credential = Mock.Of<TokenCredential>();
            var configuration = new KeyVaultConfiguration(GenerateVaultUri());
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVault(credential, configuration, cacheConfiguration));

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }
        
        [Fact]
        public void AddAzureKeyVaultSdk_WithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            var credential = Mock.Of<TokenCredential>();
            var configuration = new KeyVaultConfiguration(GenerateVaultUri());
            
            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVault(
                    credential,
                    configuration,
                    configureOptions: options => options.TrackDependency = true,
                    name: "Azure Key Vault",
                    mutateSecretName: name => "Arcus." + name,
                    cacheConfiguration: CacheConfiguration.Default);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }
        
        [Fact]
        public void AddAzureKeyVaultSdk_WithCachingWithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();
            var credential = Mock.Of<TokenCredential>();
            var configuration = new KeyVaultConfiguration(GenerateVaultUri());
            var cacheConfiguration = CacheConfiguration.Default;
            
            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVault(
                    credential,
                    configuration,
                    cacheConfiguration,
                    options => options.TrackDependency = true,
                    "Azure Key Vault",
                    name => "Arcus." + name);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                Assert.NotNull(host.Services.GetRequiredService<ISecretProvider>());
            }
        }

        private static string GenerateVaultUri()
        {
            string vaultUri = $"https://{Guid.NewGuid().ToString("N").Substring(0, 24)}.vault.azure.net/";
            return vaultUri;
        }
    }
}
