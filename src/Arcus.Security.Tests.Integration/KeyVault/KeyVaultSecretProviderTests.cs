using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Tests.Integration.KeyVault.Fixture;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    public class KeyVaultSecretProviderTests : IntegrationTest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecretProviderTests"/> class.
        /// </summary>
        public KeyVaultSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        [Fact]
        public async Task GetSecret_WithAvailableKeyVaultSecret_SucceedsByFindingSecret()
        {
            // Arrange
            await using var secret = await GivenNewKeyVaultSecretAsync();
            await using var store = GivenSecretStore(store =>
            {
                // Act
                WhenAzureKeyVaultFor(store, secret);
            });

            // Assert
            store.ShouldFindProvider<KeyVaultSecretProvider>();
            await store.ShouldFindSecretAsync(secret.SecretName, secret.SecretValue);
        }

        [Fact]
        public async Task StoreSecret_WithCachedSecret_InvalidatesSecretInStore()
        {
            // Arrange
            await using var secret = await GivenNewKeyVaultSecretAsync();
            await using var store = GivenSecretStore(store =>
            {
                WhenAzureKeyVaultFor(store, secret);
                WhenCaching(store);
            });

            var provider = store.ShouldFindProvider<KeyVaultSecretProvider>();
            string newSecretValue = $"new{Bogus.Random.Guid():N}";

            // Act
            await provider.SetSecretAsync(secret.SecretName, newSecretValue);

            // Assert
            await store.ShouldFindSecretAsync(secret.SecretName, newSecretValue);
        }

        private async Task<TemporaryKeyVaultSecret> GivenNewKeyVaultSecretAsync()
        {
            string secretName = $"name{Bogus.Random.Guid():N}";
            string secretValue = $"value{Bogus.Random.Guid()}";
            return await TemporaryKeyVaultSecret.CreateIfNotExistsAsync(secretName, secretValue, Configuration, Logger);
        }

        private void WhenAzureKeyVaultFor(SecretStoreBuilder store, TemporaryKeyVaultSecret secret)
        {
            if (Bogus.Random.Bool())
            {
                store.AddAzureKeyVault(_ => secret.Client, ConfigureOptions);
            }
            else
            {
                store.AddAzureKeyVault(secret.Client.VaultUri.ToString(), secret.Credential, ConfigureOptions);
            }
        }

        private void WhenCaching(SecretStoreBuilder store)
        {
            store.UseCaching(TimeSpan.FromHours(1));
        }
    }
}
