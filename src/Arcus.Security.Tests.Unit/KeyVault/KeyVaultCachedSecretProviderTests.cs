using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Tests.Unit.KeyVault.Doubles;
using Azure.Core;
using Moq;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault
{
    public class KeyVaultCachedSecretProviderTests
    {
        [Fact]
        public async Task StoreSecret_UsesCache_WhenWithinCacheInterval()
        {
            // Arrange
            string secretName = $"MySecret-{Guid.NewGuid()}";
            string secretValue1 = $"secret-{Guid.NewGuid()}";
            string secretValue2 = $"secret-{Guid.NewGuid()}";
            var spyProvider = new SpyKeyVaultSecretProvider(Mock.Of<TokenCredential>(), new KeyVaultConfiguration("https://some-key.vault.azure.net"));
            var cachedProvider = new KeyVaultCachedSecretProvider(spyProvider);
            await cachedProvider.StoreSecretAsync(secretName, secretValue1);

            // Act
            await cachedProvider.StoreSecretAsync(secretName, secretValue2);

            // Assert
            string actual = await cachedProvider.GetRawSecretAsync(secretName);
            Assert.Equal(secretValue2, actual);
            Assert.Equal(2, spyProvider.StoreSecretCalls);
            Assert.Equal(0, spyProvider.GetRawSecretCalls);
        }

        [Fact]
        public async Task StoreSecret_WithoutSecretName_Fails()
        {
            // Arrange
            var stubProvider = new SpyKeyVaultSecretProvider(Mock.Of<TokenCredential>(), new KeyVaultConfiguration("https://some-key.vault.azure.net"));
            var cachedProvider = new KeyVaultCachedSecretProvider(stubProvider);

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(
                () => cachedProvider.StoreSecretAsync(secretName: null, secretValue: "Some value"));
        }

        [Fact]
        public async Task StoreSecret_WithoutSecretValue_Fails()
        {
            // Arrange
            var stubProvider = new SpyKeyVaultSecretProvider(Mock.Of<TokenCredential>(), new KeyVaultConfiguration("https://some-key.vault.azure.net"));
            var cachedProvider = new KeyVaultCachedSecretProvider(stubProvider);

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(
                () => cachedProvider.StoreSecretAsync(secretName: "SomeKey", secretValue: null));
        }
    }
}
