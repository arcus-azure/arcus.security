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
        public async Task KeyVaultSecretProvider_Get_Succeeds()
        {
            // Arrange
            var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");
            
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthenticator(clientId, clientKey), 
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Act
            string secretValue = await keyVaultSecretProvider.Get(keyName);

            // Assert
            Assert.NotNull(secretValue);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_Get_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Guid.NewGuid().ToString("N");

            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthenticator(clientId, clientKey), 
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Assert
            await Assert.ThrowsAnyAsync<SecretNotFoundException>(async () =>
            {
                // Act
                await keyVaultSecretProvider.Get(keyName);
            });
        }

        [Fact]
        public async Task KeyVaultSecretProvider_GetSecret_Succeeds()
        {
            // Arrange
            var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");
            
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthenticator(clientId, clientKey), 
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Act
            Secret secret = await keyVaultSecretProvider.GetSecret(keyName);

            // Assert
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Guid.NewGuid().ToString("N");

            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                authentication: new ServicePrincipalAuthenticator(clientId, clientKey), 
                vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));

            // Assert
            await Assert.ThrowsAnyAsync<SecretNotFoundException>(async () =>
            {
                // Act
                await keyVaultSecretProvider.GetSecret(keyName);
            });
        }
    }
}
