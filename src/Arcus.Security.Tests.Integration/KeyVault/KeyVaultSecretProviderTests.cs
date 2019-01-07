using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Secrets.Core.Exceptions;
using Arcus.Security.Secrets.AzureKeyVault;
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
        public async Task KeyVaultSecretProvider_GetSecret_Succeeds()
        {
            // Arrange
            var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            // Act
            KeyVaultSecretProvider keyVaultSecretProvider = new KeyVaultSecretProvider(
                new ServicePrincipalAuthenticator(clientId, clientKey), new KeyVaultConfiguration(keyVaultUri)
                );
            string secretValue = await keyVaultSecretProvider.Get(keyName);

            // Assert
            Assert.NotNull(secretValue);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_GetNonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Guid.NewGuid().ToString("N");

            // Act
            KeyVaultSecretProvider keyVaultSecretProvider = new KeyVaultSecretProvider(
                new ServicePrincipalAuthenticator(clientId, clientKey), new KeyVaultConfiguration(keyVaultUri)
            );

            // Assert
            await Assert.ThrowsAnyAsync<SecretNotFoundException>(async () =>
            {
                await keyVaultSecretProvider.Get(keyName);
            });
        }
    }
}
