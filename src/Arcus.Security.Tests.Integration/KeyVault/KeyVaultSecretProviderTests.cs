using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Secrets.Core.Exceptions;
using Arcus.Security.Secrets.AzureKeyVault;
using Arcus.Security.Secrets.Core.Models;
using Microsoft.Extensions.Configuration;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    [Trait(name: "Category", value: "Integration")]
    public class KeyVaultSecretProviderTests : IntegrationTest
    {
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
                authentication: new ServicePrincipalAuthenticator(applicationId, clientKey), 
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
            var notExistingKeyName = Guid.NewGuid().ToString("N");

            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthenticator(applicationId, clientKey), 
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
            var notExistingKeyName = Guid.NewGuid().ToString("N");
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
            const string environmentVariableName = "AzureServicesAuthConnectionString";

            try
            {
                // Arrange
                var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
                var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
                var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");
                var keyVaultSecretProvider = new KeyVaultSecretProvider(
                    authentication: new ManagedServiceIdentityAuthentication(),
                    vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

                Environment.SetEnvironmentVariable(environmentVariableName, connectionString);

                // Act
                Secret secret = await keyVaultSecretProvider.GetSecretAsync(keyName);

                // Assert
                Assert.NotNull(secret);
                Assert.NotNull(secret.Value);
                Assert.NotNull(secret.Version);
            }
            finally
            {
                Environment.SetEnvironmentVariable(environmentVariableName, value: null);
            }
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithDefaultManagedServiceIdentity_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            const string environmentVariableName = "AzureServicesAuthConnectionString";

            try
            {
                // Arrange
                var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
                var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
                var notExistingKeyName = Guid.NewGuid().ToString("N");
                var keyVaultSecretProvider = new KeyVaultSecretProvider(
                    authentication: new ManagedServiceIdentityAuthentication(),
                    vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

                Environment.SetEnvironmentVariable(environmentVariableName, connectionString);

                // Assert
                await Assert.ThrowsAsync<SecretNotFoundException>(async () =>
                {
                // Act
                await keyVaultSecretProvider.GetSecretAsync(notExistingKeyName);
                });
            }
            finally
            {
                Environment.SetEnvironmentVariable(environmentVariableName, value: null);
            }
        }
    }
}
