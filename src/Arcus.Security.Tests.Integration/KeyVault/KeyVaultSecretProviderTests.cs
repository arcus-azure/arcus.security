using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Tests.Core.Fixture;
using Azure.Identity;
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
            var secretName = Configuration.GetValue<string>("Arcus:KeyVault:TestSecretName");
            
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthentication(applicationId, clientKey), 
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Act
            Secret secret = await keyVaultSecretProvider.GetSecretAsync(secretName);

            // Assert
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithServicePrincipalWithTenant_GetSecret_Succeeds()
        {
            // Arrange
            string tenantId = Configuration.GetTenantId();
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var secretName = Configuration.GetValue<string>("Arcus:KeyVault:TestSecretName");
            
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                tokenCredential: new ClientSecretCredential(tenantId, applicationId, clientKey), 
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Act
            Secret secret = await keyVaultSecretProvider.GetSecretAsync(secretName);

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
            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";

            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthentication(applicationId, clientKey), 
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Assert
            await Assert.ThrowsAnyAsync<SecretNotFoundException>(async () =>
            {
                // Act
                await keyVaultSecretProvider.GetSecretAsync(notExistingSecretName);
            });
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithServicePrincipalWithTenant_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            string tenantId = Configuration.GetTenantId();
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";

            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                tokenCredential: new ClientSecretCredential(tenantId, applicationId, clientKey), 
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Assert
            await Assert.ThrowsAnyAsync<SecretNotFoundException>(async () =>
            {
                // Act
                await keyVaultSecretProvider.GetSecretAsync(notExistingSecretName);
            });
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithManagedIdentity_GetSecret_Succeeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var secretName = Configuration.GetValue<string>("Arcus:KeyVault:TestSecretName");
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(connectionString: connectionString),
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Act
            Secret secret = await keyVaultSecretProvider.GetSecretAsync(secretName);

            // Assert
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithUserAssignedManagedIdentity_GetSecret_Succeeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            string clientId = Configuration.GetServicePrincipalClientId();
            string clientKey = Configuration.GetServicePrincipalClientSecret();
            var secretName = Configuration.GetValue<string>("Arcus:KeyVault:TestSecretName");

            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientKey))
            {
                var keyVaultSecretProvider = new KeyVaultSecretProvider(
                        tokenCredential: new ChainedTokenCredential(new ManagedIdentityCredential(clientId), new EnvironmentCredential()),
                        vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

                // Act
                Secret secret = await keyVaultSecretProvider.GetSecretAsync(secretName);

                // Assert
                Assert.NotNull(secret);
                Assert.NotNull(secret.Value);
                Assert.NotNull(secret.Version); 
            }
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithManagedIdentity_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(connectionString: connectionString),
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Assert
            await Assert.ThrowsAsync<SecretNotFoundException>(async () =>
            {
                // Act
                await keyVaultSecretProvider.GetSecretAsync(notExistingSecretName);
            });
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithUserAssignedManagedIdentity_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            string clientId = Configuration.GetServicePrincipalClientId();
            string clientKey = Configuration.GetServicePrincipalClientSecret();

            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientKey))
            {
                var notExistingSecretName = $"secret-{Guid.NewGuid():N}";
                var keyVaultSecretProvider = new KeyVaultSecretProvider(
                    tokenCredential: new ChainedTokenCredential(new ManagedIdentityCredential(clientId), new EnvironmentCredential()),
                    vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

                // Assert
                await Assert.ThrowsAsync<SecretNotFoundException>(async () =>
                {
                // Act
                await keyVaultSecretProvider.GetSecretAsync(notExistingSecretName);
                }); 
            }
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithDefaultManagedServiceIdentity_GetSecret_Succeeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var secretName = Configuration.GetValue<string>("Arcus:KeyVault:TestSecretName");
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(),
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            using (TemporaryEnvironmentVariable.Create(KeyVaultConnectionStringEnvironmentVariable, connectionString))
            {
                // Act
                Secret secret = await keyVaultSecretProvider.GetSecretAsync(secretName);

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
            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(),
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            using (TemporaryEnvironmentVariable.Create(KeyVaultConnectionStringEnvironmentVariable, connectionString))
            {
                // Assert
                await Assert.ThrowsAsync<SecretNotFoundException>(async () =>
                {
                    // Act
                    await keyVaultSecretProvider.GetSecretAsync(notExistingSecretName);
                });
            }
        }

        [Fact]
        public async Task KeyVaultSecretProvider_StoreSecret_Succeeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var secretName = $"Test-Secret-{Guid.NewGuid()}";
            var secretValue = Guid.NewGuid().ToString();
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(),
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            using (TemporaryEnvironmentVariable.Create(KeyVaultConnectionStringEnvironmentVariable, connectionString))
            {
                // Act
                Secret secret = await keyVaultSecretProvider.StoreSecretAsync(secretName, secretValue);

                // Assert
                Assert.NotNull(secret);
                Assert.NotNull(secret.Value);
                Assert.NotNull(secret.Version);
                Secret fetchedSecret = await keyVaultSecretProvider.GetSecretAsync(secretName);
                Assert.Equal(secretValue, fetchedSecret.Value);
                Assert.Equal(secret.Version, fetchedSecret.Version);
                Assert.Equal(secret.Expires, fetchedSecret.Expires);
            }
        }

        [Fact]
        public async Task KeyVaultSecretProvider__StoreSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";
            var secretValue = Guid.NewGuid().ToString();
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(),
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            using (TemporaryEnvironmentVariable.Create(KeyVaultConnectionStringEnvironmentVariable, connectionString))
            {
                // Assert
                await Assert.ThrowsAsync<SecretNotFoundException>(async () =>
                {
                    // Act
                    await keyVaultSecretProvider.StoreSecretAsync(notExistingSecretName, secretValue);
                });
            }
        }
    }
}
