using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Tests.Core.Fixture;
using Microsoft.Extensions.Configuration;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    [Trait(name: "Category", value: "Integration")]
    public class KeyVaultSecretProviderTests : IntegrationTest
    {
        private const string KeyVaultConnectionStringEnvironmentVariable = "AzureServicesAuthConnectionString";

        // The same tests should be tested with different KeyVaultClientFactories 
        // What's the best approach for this ?

        public KeyVaultSecretProviderTests(ITestOutputHelper testOutput) : base(testOutput)
        {
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithServicePrincipal_GetSecret_Succeeds()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");
            
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthentication(applicationId, clientKey), 
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Act
            Secret secret = await keyVaultSecretProvider.GetSecretAsync(keyName);

            // Assert
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithServicePrincipal_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var notExistingKeyName = $"secret-{Guid.NewGuid():N}";

            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthentication(applicationId, clientKey), 
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Assert
            await Assert.ThrowsAnyAsync<SecretNotFoundException>(async () =>
            {
                // Act
                await keyVaultSecretProvider.GetSecretAsync(notExistingKeyName);
            });
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithCustomManagedServiceIdentity_GetSecret_Succeeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(connectionString: connectionString),
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Act
            Secret secret = await keyVaultSecretProvider.GetSecretAsync(keyName);

            // Assert
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithCustomManagedServiceIdentity_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var notExistingKeyName = $"secret-{Guid.NewGuid():N}";
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(connectionString: connectionString),
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Assert
            await Assert.ThrowsAsync<SecretNotFoundException>(async () =>
            {
                // Act
                await keyVaultSecretProvider.GetSecretAsync(notExistingKeyName);
            });
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithDefaultManagedServiceIdentity_GetSecret_Succeeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(),
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            using (TemporaryEnvironmentVariable.Create(KeyVaultConnectionStringEnvironmentVariable, connectionString))
            {
                // Act
                Secret secret = await keyVaultSecretProvider.GetSecretAsync(keyName);

                // Assert
                Assert.NotNull(secret);
                Assert.NotNull(secret.Value);
                Assert.NotNull(secret.Version);
            }
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithDefaultManagedServiceIdentity_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var notExistingKeyName = $"secret-{Guid.NewGuid():N}";
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(),
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            using (TemporaryEnvironmentVariable.Create(KeyVaultConnectionStringEnvironmentVariable, connectionString))
            {
                // Assert
                await Assert.ThrowsAsync<SecretNotFoundException>(async () =>
                {
                    // Act
                    await keyVaultSecretProvider.GetSecretAsync(notExistingKeyName);
                });
            }
        }
    }
}
