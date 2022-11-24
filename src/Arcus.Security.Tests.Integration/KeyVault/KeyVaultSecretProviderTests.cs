using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Tests.Core.Fixture;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
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

        private string TenantId => Configuration.GetTenantId();
        private string ClientId => Configuration.GetRequiredValue("Arcus:ServicePrincipal:ApplicationId");
        private string ClientSecret => Configuration.GetRequiredValue("Arcus:ServicePrincipal:AccessKey");
        private string TestSecretName => Configuration.GetRequiredValue("Arcus:KeyVault:TestKeyName");
        private string VaultUri => Configuration.GetRequiredValue("Arcus:KeyVault:Uri");
        private string TestSecretVersion => Configuration.GetRequiredValue("Arcus:KeyVault:TestKeyVersion");

        [Fact]
        public async Task KeyVaultSecretProvider_WithServicePrincipal_GetSecret_Succeeds()
        {
            // Arrange
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthentication(ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Act / Assert
            AssertNotNullSecret(await keyVaultSecretProvider.GetSecretAsync(TestSecretName));
            AssertNotNullSecret(await keyVaultSecretProvider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithServicePrincipalWithTenant_GetSecret_Succeeds()
        {
            // Arrange
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                tokenCredential: new ClientSecretCredential(TenantId, ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Act / Assert
            AssertNotNullSecret(keyVaultSecretProvider.GetSecret(TestSecretName));
            AssertNotNullSecret(keyVaultSecretProvider.GetRawSecret(TestSecretName));
            AssertNotNullSecret(await keyVaultSecretProvider.GetSecretAsync(TestSecretName));
            AssertNotNullSecret(await keyVaultSecretProvider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithServicePrincipal_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";

            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthentication(ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

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
            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";

            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                tokenCredential: new ClientSecretCredential(TenantId, ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

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
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(connectionString: connectionString),
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Act / Assert
            AssertNotNullSecret(await keyVaultSecretProvider.GetSecretAsync(TestSecretName));
            AssertNotNullSecret(await keyVaultSecretProvider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithUserAssignedManagedIdentity_GetSecret_Succeeds()
        {
            // Arrange
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                var keyVaultSecretProvider = new KeyVaultSecretProvider(
                        tokenCredential: new ChainedTokenCredential(new ManagedIdentityCredential(ClientId), new EnvironmentCredential()),
                        vaultConfiguration: new KeyVaultConfiguration(VaultUri));

                // Act / Assert
                AssertNotNullSecret(keyVaultSecretProvider.GetSecret(TestSecretName));
                AssertNotNullSecret(keyVaultSecretProvider.GetRawSecret(TestSecretName));
                AssertNotNullSecret(await keyVaultSecretProvider.GetSecretAsync(TestSecretName));
                AssertNotNullSecret(await keyVaultSecretProvider.GetRawSecretAsync(TestSecretName));
            }
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithManagedIdentity_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(connectionString: connectionString),
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

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
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                var notExistingSecretName = $"secret-{Guid.NewGuid():N}";
                var keyVaultSecretProvider = new KeyVaultSecretProvider(
                    tokenCredential: new ChainedTokenCredential(new ManagedIdentityCredential(ClientId), new EnvironmentCredential()),
                    vaultConfiguration: new KeyVaultConfiguration(VaultUri));

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
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(),
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            using (TemporaryEnvironmentVariable.Create(KeyVaultConnectionStringEnvironmentVariable, connectionString))
            {
                // Act / Assert
                AssertNotNullSecret(await keyVaultSecretProvider.GetSecretAsync(TestSecretName));
                AssertNotNullSecret(await keyVaultSecretProvider.GetRawSecretAsync(TestSecretName));
            }
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithDefaultManagedServiceIdentity_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ManagedServiceIdentityAuthentication(),
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

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
            var secretName = $"Test-Secret-{Guid.NewGuid()}";
            var secretValue = Guid.NewGuid().ToString();

            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                var tokenCredential = new ChainedTokenCredential(new ManagedIdentityCredential(ClientId), new EnvironmentCredential());
                try
                {
                    var keyVaultSecretProvider = new KeyVaultSecretProvider(
                        tokenCredential: tokenCredential,
                        vaultConfiguration: new KeyVaultConfiguration(VaultUri));

                    // Act
                    Secret secret = await keyVaultSecretProvider.StoreSecretAsync(secretName, secretValue);

                    // Assert
                    AssertNotNullSecret(secretValue);
                    Secret fetchedSecret = await keyVaultSecretProvider.GetSecretAsync(secretName);
                    Assert.Equal(secretValue, fetchedSecret.Value);
                    Assert.Equal(secret.Version, fetchedSecret.Version);
                    Assert.Equal(secret.Expires, fetchedSecret.Expires);
                }
                finally
                {
                    var client = new SecretClient(new Uri(VaultUri), tokenCredential);
                    await client.StartDeleteSecretAsync(secretName);
                }
            }
        }

        [Fact]
        public async Task NewKeyVaultSecretProvider_ReturnsManySecrets_Succeeds()
        {
            // Arrange
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                tokenCredential: new ClientSecretCredential(TenantId, ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Act
            IEnumerable<Secret> secrets = await keyVaultSecretProvider.GetSecretsAsync(TestSecretName, amountOfVersions: 2);

            // Assert
            Assert.Equal(2, secrets.Count());
            Assert.Equal(TestSecretVersion, secrets.ElementAt(0).Version);
        }

        [Fact]
        public async Task OldKeyVaultSecretProvider_ReturnsManySecrets_Succeeds()
        {
            // Arrange
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                new ServicePrincipalAuthentication(ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Act
            IEnumerable<Secret> secrets = await keyVaultSecretProvider.GetSecretsAsync(TestSecretName, amountOfVersions: 2);

            // Assert
            Assert.Equal(2, secrets.Count());
            Assert.Equal(TestSecretVersion, secrets.ElementAt(0).Version);
        }

        [Fact]
        public async Task NewKeyVaultSecretProvider_ReturnsOnlyAvailableSecrets_Succeeds()
        {
            // Arrange
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                tokenCredential: new ClientSecretCredential(TenantId, ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Act
            IEnumerable<Secret> secrets = await keyVaultSecretProvider.GetSecretsAsync(TestSecretName, amountOfVersions: 10);

            // Assert
            Assert.Equal(2, secrets.Count());
            Assert.Equal(TestSecretVersion, secrets.ElementAt(0).Version);
        }

        [Fact]
        public async Task OldKeyVaultSecretProvider_ReturnsOnlyAvailableSecrets_Succeeds()
        {
            // Arrange
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                new ServicePrincipalAuthentication(ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Act
            IEnumerable<Secret> secrets = await keyVaultSecretProvider.GetSecretsAsync(TestSecretName, amountOfVersions: 10);

            // Assert
            Assert.Equal(2, secrets.Count());
            Assert.Equal(TestSecretVersion, secrets.ElementAt(0).Version);
        }

        private void AssertNotNullSecret(Secret secret)
        {
            Assert.NotNull(secret);
            AssertNotNullSecret(secret.Value);
            Assert.NotNull(secret.Version);
        }

        private void AssertNotNullSecret(string secretValue)
        {
            Assert.NotNull(secretValue);
        }
    }
}
