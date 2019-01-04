using System;
using Arcus.Security.Secrets.Providers.AzureKeyVault;
using Arcus.Security.Tests.Unit.KeyVault.Stubs;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault
{
    public class KeyVaultSecretProviderTests
    {
        [Fact]
        public void KeyVaultSecretProvider_CreateWithEmptyUri_ShouldFailWithArgumentException()
        {
            // Arrange
            string uri = string.Empty;

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider(new KeyVaultClientFactoryStub(), uri));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithoutUri_ShouldFailWithArgumentException()
        {
            // Arrange
            string uri = null;

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider(new KeyVaultClientFactoryStub(), uri));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithoutClientFactory_ShouldFailWithArgumentException()
        {
            // Arrange
            string uri = Guid.NewGuid().ToString("N");

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider(null, uri));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithValidArguments_ShouldSucceed()
        {
            // Arrange
            string uri = Guid.NewGuid().ToString("N");

            // Act & Assert
            var secretProvider = new KeyVaultSecretProvider(new KeyVaultClientFactoryStub(), uri);
            Assert.NotNull(secretProvider);
        }
    }
}
