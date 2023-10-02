using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Integration.KeyVault.Configuration;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    [Trait(name: "Category", value: "Integration")]
    public class KeyVaultCachedSecretProviderTests : IntegrationTest
    {
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
            var keyVault = Configuration.GetKeyVaultConfig();
            string clientId = keyVault.ServicePrincipal.ClientId;

            var secretName = $"Test-Secret-{Guid.NewGuid()}";
            var secretValue = Guid.NewGuid().ToString();
            
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, keyVault.Azure.TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, keyVault.ServicePrincipal.ClientSecret))
            {
                var tokenCredential = new ChainedTokenCredential(
                    new ManagedIdentityCredential(clientId),
                    new EnvironmentCredential());
                
                var cachedSecretProvider = new KeyVaultCachedSecretProvider(
                    new KeyVaultSecretProvider(
                        tokenCredential, new KeyVaultConfiguration(keyVault.VaultUri)));

                try
                {
                    // Act
                    Secret secret = await cachedSecretProvider.StoreSecretAsync(secretName, secretValue);

                    // Assert
                    Assert.NotNull(secret);
                    Assert.NotNull(secret.Value);
                    Assert.NotNull(secret.Version);
                    AssertEqualSecret(secret, cachedSecretProvider.GetSecret(secretName));
                    AssertEqualSecret(secret, cachedSecretProvider.GetRawSecret(secretName));
                    AssertEqualSecret(secret, await cachedSecretProvider.GetSecretAsync(secretName));
                    AssertEqualSecret(secret, await cachedSecretProvider.GetRawSecretAsync(secretName));
                }
                finally
                {
                    var client = new SecretClient(new Uri(keyVault.VaultUri), tokenCredential);
                    await client.StartDeleteSecretAsync(secretName);
                }
            }
        }

        private static void AssertEqualSecret(Secret expected, string secretValue)
        {
            Assert.Equal(expected.Value, secretValue);
        }

        private static void AssertEqualSecret(Secret expected, Secret actual)
        {
            Assert.Equal(expected.Value, actual.Value);
            Assert.Equal(expected.Version, actual.Version);
            Assert.Equal(expected.Expires, actual.Expires);
        }
    }
}
