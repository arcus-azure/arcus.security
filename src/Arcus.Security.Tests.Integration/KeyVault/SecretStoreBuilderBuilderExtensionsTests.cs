using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Tests.Integration.Fixture;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    [Trait(name: "Category", value: "Integration")]
    public class SecretStoreBuilderBuilderExtensionsTests : IntegrationTest
    {
        public SecretStoreBuilderBuilderExtensionsTests(ITestOutputHelper testOutput) : base(testOutput)
        {
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, applicationId, clientKey);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipal_GetSecretFails()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = "Unknown.Secret.Name";

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, applicationId, clientKey);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipalToDots_GetsSecretSucceeds()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, applicationId, clientKey, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Test-" + keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipalWrongMutation_GetsSecretsFails()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, applicationId, clientKey, mutateSecretName: secretName => "SOMETHING_WRONG_" + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, applicationId, clientKey, allowCaching: true);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipal_GetSecretFails()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = "Unknown.Secret.Name";

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, applicationId, clientKey, allowCaching: true);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipalRemovesPrefix_GetsSecretsSucceeds()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, applicationId, clientKey, allowCaching: true, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Test-" + keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipalWrongMutation_GetsSecretFails()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, applicationId, clientKey, allowCaching: true, mutateSecretName: secretName => "SOMETHING_WRONG_" + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentity_GetSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, connectionString));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentity_GetSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = "Unknown.Secret.Name";

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, connectionString);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(
                    keyVaultUri, connectionString, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Test-" + keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(
                    keyVaultUri, connectionString, mutateSecretName: secretName => "SOMETHING_WRONG_" + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentity_GetSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, connectionString: connectionString, cacheConfiguration: cacheConfiguration);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
            Assert.True(cacheConfiguration.IsCalled);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentity_GetSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = "Unknown.Secret.Name";

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, connectionString: connectionString, cacheConfiguration: cacheConfiguration);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(
                    keyVaultUri, connectionString: connectionString, cacheConfiguration: cacheConfiguration, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Test-" + keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
            Assert.True(cacheConfiguration.IsCalled);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(
                    keyVaultUri, connectionString: connectionString, cacheConfiguration: cacheConfiguration, mutateSecretName: secretName => "SOMETHING_WRONG_" + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }
    }
}
