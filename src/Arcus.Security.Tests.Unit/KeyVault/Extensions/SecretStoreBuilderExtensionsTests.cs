using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Azure.Core;
using Microsoft.Azure.KeyVault.Core;
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
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "client-id", new X509Certificate2()));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateWithOptions_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificateWithOptions(vaultUri, "client-id", new X509Certificate2()));

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

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "client-id", new X509Certificate2(), cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateWithOptions_WithCachingWithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificateWithOptions(vaultUri, "client-id", new X509Certificate2(), cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimple_WithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", certificate));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimpleCacheConfiguration_WithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", certificate, cacheConfiguration: new CacheConfiguration()));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificate_WithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), clientId, new X509Certificate2()));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateWithOptions_WithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificateWithOptions(GenerateVaultUri(), clientId, new X509Certificate2()));

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

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), clientId, new X509Certificate2(), cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateWithOptions_WithCachingWithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificateWithOptions(GenerateVaultUri(), clientId, new X509Certificate2(), cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimple_WithoutClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), clientId, "tenant-id", certificate));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimpleCacheConfiguration_WithoutClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), clientId, "tenant-id", certificate, cacheConfiguration: new CacheConfiguration()));
            
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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "client-id", certificate: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultWithCertificateWithOptions_WithoutCertificate_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificateWithOptions(GenerateVaultUri(), "client-id", certificate: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "client-id", certificate: null, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultWithCertificateWithOptions_WithCachingWithoutCertificate_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificateWithOptions(GenerateVaultUri(), "client-id", certificate: null, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimple_WithoutTenant_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), tenantId, "client-id", certificate));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateSimpleCacheConfiguration_WithoutTenant_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();
            var certificate = new X509Certificate2();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), tenantId, "client-id", certificate, cacheConfiguration: new CacheConfiguration()));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", new X509Certificate2(), configureOptions: null, name: null, mutateSecretName: null));

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

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", new X509Certificate2(), cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", clientId, new X509Certificate2(), configureOptions: null, name: null, mutateSecretName: null));

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

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", clientId, new X509Certificate2(), cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", "client-id", certificate: null, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", "client-id", certificate: null, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultWithCertificateSimple_WithoutCertificate_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", "client-id", certificate: null));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultWithCertificateSimpleCacheConfiguration_WithoutCertificate_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), "tenant-id", "client-id", certificate: null, cacheConfiguration: new CacheConfiguration()));
            
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

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), tenantId, "client-id", new X509Certificate2(), cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

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

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(), tenantId, "client-id", new X509Certificate2(), cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Fact]
        public void AddAzureKeyVaultWithCertificateUsingTenant_WithValidArguments_CreatesProvider()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(),
                    "tenant-id",
                    "client-id",
                    new X509Certificate2(),
                    configureOptions: options => options.TrackDependency = true,
                    name: "Azure Key Vault",
                    mutateSecretName: name => name.Replace(":", "."),
                    allowCaching: true);
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
            var cacheConfiguration = new CacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithCertificate(GenerateVaultUri(),
                    "tenant-id",
                    "client-id",
                    new X509Certificate2(),
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
        public void AddAzureKeyVaultWithManagedServiceIdentity_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithManagedServiceIdentity(vaultUri));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedServiceIdentityWithOptions_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithManagedServiceIdentityWithOptions(vaultUri));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedServiceIdentity_WithCachingWithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithManagedServiceIdentity(vaultUri, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
       
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentitySimple_WithoutVaultUriWithoutClientId_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri));

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
                (config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, "client-id"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentitySimpleCacheConfiguration_WithoutVaultUriWithoutClientId_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedIdentitySimpleCacheConfiguration_WithoutVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, cacheConfiguration, "client-id"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithManagedServiceIdentityWithOptions_WithCachingWithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithManagedServiceIdentityWithOptions(vaultUri, cacheConfiguration: cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, clientId: null, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, cacheConfiguration: cacheConfiguration, clientId: null, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) =>
                {
                    stores.AddAzureKeyVaultWithManagedIdentity(
                        GenerateVaultUri(),
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
                (config, stores) =>
                {
                    stores.AddAzureKeyVaultWithManagedIdentity(
                        GenerateVaultUri(),
                        "client-id",
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
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) =>
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
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) =>
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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "client-id", "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithOptions_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipalWithOptions(vaultUri, "client-id", "client-secret"));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "client-id", "client-secret", cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithOptions_WithCachingWithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipalWithOptions(vaultUri, "client-id", "client-secret", cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimpleCacheConfiguration_WithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret", cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), clientId, "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithOptions_WithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipalWithOptions(GenerateVaultUri(), clientId, "client-secret"));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), clientId, "client-secret", cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithOptions_WithCachingWithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipalWithOptions(GenerateVaultUri(), clientId, "client-secret", cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), tenantId, "client-id", "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimpleCacheConfiguration_WithoutTenantId_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), tenantId, "client-id", "client-secret", cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", clientId, "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimpleCacheConfiguration_WithoutClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", clientId, "client-secret", cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "client-id", clientSecret));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithOptions_WithBlankClientSecret_Throws(string clientSecret)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipalWithOptions(GenerateVaultUri(), "client-id", clientSecret));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "client-id", clientSecret, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithOptions_WithCachingWithBlankClientSecret_Throws(string clientSecret)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipalWithOptions(GenerateVaultUri(), "client-id", clientSecret, cacheConfiguration: cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", "client-id", clientKey));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
        
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalSimpleCacheConfiguration_WithoutClientKey_Throws(string clientKey)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", "client-id", clientKey, cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret", configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret", cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", clientId, "client-secret", configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", clientId, "client-secret", cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddAzureKeyVaultWithServicePrincipalWithTenant_WithBlankClientSecret_Throws(string tenantId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", "client-id", tenantId, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), "tenant-id", "client-id", clientSecret, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), tenantId, "client-id", "client-secret", cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(GenerateVaultUri(), tenantId, "client-id", "client-secret", configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) =>
                {
                    stores.AddAzureKeyVaultWithServicePrincipal(
                        GenerateVaultUri(),
                        "tenant-id",
                        "client-id",
                        "client-secret",
                        configureOptions: options => options.TrackDependency = true,
                        name: "Azure Key Vault",
                        mutateSecretName: name => name.Replace(":", "."),
                        allowCaching: true);
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
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore(
                (config, stores) =>
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
        public void AddAzureKeyVault_WithoutAuthentication_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var configuration = Mock.Of<IKeyVaultConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVault(authentication: null, configuration: configuration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultWithOptions_WithoutAuthentication_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var configuration = Mock.Of<IKeyVaultConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithOptions(authentication: null, configuration: configuration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVault_WithCachingWithoutAuthentication_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var configuration = Mock.Of<IKeyVaultConfiguration>();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVault(authentication: null, configuration: configuration, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultWithOptions_WithCachingWithoutAuthentication_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var configuration = Mock.Of<IKeyVaultConfiguration>();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithOptions(authentication: null, configuration: configuration, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVault_WithoutVaultConfiguration_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var authentication = Mock.Of<IKeyVaultAuthentication>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVault(authentication, configuration: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultWithOptions_WithoutVaultConfiguration_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var authentication = Mock.Of<IKeyVaultAuthentication>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithOptions(authentication, configuration: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddAzureKeyVaultSdkSimple_WithoutVaultConfiguration_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var credential = Mock.Of<TokenCredential>();
            
            // Act
            builder.ConfigureSecretStore((config, stores) =>
                stores.AddAzureKeyVault(tokenCredential: credential, configuration: null));
            
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
                (config, stores) => stores.AddAzureKeyVault(credential, configuration: null, allowCaching: false, configureOptions: null, name: null, mutateSecretName: null));

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
            builder.ConfigureSecretStore((config, stores) =>
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
                (config, stores) => stores.AddAzureKeyVault(credential, configuration: null, cacheConfiguration: cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVault(credential, configuration: null, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVault(tokenCredential: null, configuration: configuration, allowCaching: false, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVault(tokenCredential: null, configuration: configuration, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null));

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
                (config, stores) => stores.AddAzureKeyVault(tokenCredential: null, configuration: configuration, cacheConfiguration: cacheConfiguration));

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
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVault(credential, configuration));

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
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVault(credential, configuration, cacheConfiguration));

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
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVault(
                    credential,
                    configuration,
                    options => options.TrackDependency = true,
                    "Azure Key Vault",
                    name => "Arcus." + name,
                    allowCaching: true);
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
            var cacheConfiguration = new CacheConfiguration();
            
            // Act
            builder.ConfigureSecretStore((config, stores) =>
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
