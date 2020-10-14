using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Azure.Core;
using Microsoft.Extensions.Hosting;
using Moq;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault
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
        public void AddAzureKeyVaultWithCertificate_WithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithCertificate("vault-uri", clientId, new X509Certificate2()));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate("vault-uri", clientId, new X509Certificate2(), cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate("vault-uri", "client-id", certificate: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate("vault-uri", "client-id", certificate: null, cacheConfiguration: cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", new X509Certificate2()));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate(vaultUri, "tenant-id", "client-id", new X509Certificate2(), cacheConfiguration: cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate("vault-uri", "tenant-id", clientId, new X509Certificate2()));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate("vault-uri", "tenant-id", clientId, new X509Certificate2(), cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate("vault-uri", "tenant-id", "client-id", certificate: null));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate("vault-uri", "tenant-id", "client-id", certificate: null, cacheConfiguration: cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate("vault-uri", tenantId, "client-id", new X509Certificate2(), cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithCertificate("vault-uri", tenantId, "client-id", new X509Certificate2()));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
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
        public void AddAzureKeyVaultWithManagedIdentity_WithBlankVaultUri_Throws(string vaultUri)
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
        public void AddAzureKeyVaultWithManagedIdentity_WithCachingWithBlankVaultUri_Throws(string vaultUri)
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = Mock.Of<ICacheConfiguration>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(vaultUri, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
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
        public void AddAzureKeyVaultWithServicePrincipal_WithBlankClientId_Throws(string clientId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal("vault-uri", clientId, "client-secret"));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal("vault-uri", clientId, "client-secret", cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal("vault-uri", "client-id", clientSecret));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal("vault-uri", "client-id", clientSecret, cacheConfiguration: cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret"));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(vaultUri, "tenant-id", "client-id", "client-secret", cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal("vault-uri", "tenant-id", clientId, "client-secret"));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal("vault-uri", "tenant-id", clientId, "client-secret", cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal("vault-uri", "tenant-id", "client-id", tenantId));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal("vault-uri", "tenant-id", "client-id", clientSecret, cacheConfiguration: cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal("vault-uri", tenantId, "client-id", "client-secret", cacheConfiguration: cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVaultWithServicePrincipal("vault-uri", tenantId, "client-id", "client-secret"));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
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
        public void AddAzureKeyVaultSdk_WithoutVaultConfiguration_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            var credential = Mock.Of<TokenCredential>();

            // Act
            builder.ConfigureSecretStore(
                (config, stores) => stores.AddAzureKeyVault(credential, configuration: null, allowCaching: false));

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
                (config, stores) => stores.AddAzureKeyVault(credential, configuration: null, cacheConfiguration: cacheConfiguration));

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
                (config, stores) => stores.AddAzureKeyVault(tokenCredential: null, configuration: configuration, allowCaching: false));

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
                (config, stores) => stores.AddAzureKeyVault(tokenCredential: null, configuration: configuration, cacheConfiguration: cacheConfiguration));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
    }
}
