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
    public class KeyVaultCachedSecretProviderTests : IntegrationTest
    {
        private const string KeyVaultConnectionStringEnvironmentVariable = "AzureServicesAuthConnectionString";

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultCachedSecretProviderTests"/> class.
        /// </summary>
        public KeyVaultCachedSecretProviderTests(ITestOutputHelper testOutput) : base(testOutput)
        {
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

            var cachedSecretProvider = new KeyVaultCachedSecretProvider(keyVaultSecretProvider);

            using (TemporaryEnvironmentVariable.Create(KeyVaultConnectionStringEnvironmentVariable, connectionString))
            {
                // Act
                Secret secret = await cachedSecretProvider.StoreSecretAsync(secretName, secretValue);

                // Assert
                Assert.NotNull(secret);
                Assert.NotNull(secret.Value);
                Assert.NotNull(secret.Version);
                Secret fetchedSecret = await cachedSecretProvider.GetSecretAsync(secretName);
                Assert.Equal(secretValue, fetchedSecret.Value);
                Assert.Equal(secret.Version, fetchedSecret.Version);
                Assert.Equal(secret.Expires, fetchedSecret.Expires);
            }
        }
    }
}
