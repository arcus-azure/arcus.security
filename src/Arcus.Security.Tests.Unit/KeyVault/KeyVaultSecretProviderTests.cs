using System;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Secrets.AzureKeyVault;
using Arcus.Security.Tests.Unit.KeyVault.Stubs;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault
{
    public class KeyVaultSecretProviderTests
    {
        [Fact]
        public void KeyVaultSecretProvider_CreateWithEmptyUri_ShouldFailWithUriFormatException()
        {
            // Arrange
            string uri = string.Empty;

            // Act & Assert
            Assert.ThrowsAny<UriFormatException>(() => new KeyVaultSecretProvider(new KeyVaultClientFactoryStub(), new KeyVaultConfiguration(uri)));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithHttpScheme_ShouldFailWithUriFormatException()
        {
            // Arrange
            string uri = $"http://{Guid.NewGuid():N}.vault.azure.net/";

            // Act & Assert
            Assert.ThrowsAny<UriFormatException>(() => new KeyVaultSecretProvider(null, new KeyVaultConfiguration(uri)));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithoutUri_ShouldFailWithArgumentException()
        {
            // Arrange
            string uri = null;

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider(new KeyVaultClientFactoryStub(), new KeyVaultConfiguration(uri)));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithoutClientFactory_ShouldFailWithArgumentException()
        {
            // Arrange
            string uri = $"https://{Guid.NewGuid():N}.vault.azure.net/";

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider(null, new KeyVaultConfiguration(uri)));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithValidArguments_ShouldSucceed()
        {
            // Arrange
            string uri = $"https://{Guid.NewGuid():N}.vault.azure.net/";

            // Act & Assert
            var secretProvider = new KeyVaultSecretProvider(new KeyVaultClientFactoryStub(), new KeyVaultConfiguration(uri));
            Assert.NotNull(secretProvider);
        }
    }
}
