using Arcus.Security.Providers.AzureKeyVault.Configuration;
using System;
using Arcus.Security.Providers.AzureKeyVault;
using Azure.Core;
using Moq;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault
{
    public class KeyVaultSecretProviderTests
    {
        [Fact]
        public void KeyVaultSecretProvider_WithoutTokenCredential_Throws()
        {
            // Arrange
            var config = Mock.Of<IKeyVaultConfiguration>();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(
                () => new KeyVaultSecretProvider(tokenCredential: null, vaultConfiguration: config));
        }

        [Fact]
        public void KeyVaultSecretProvider_WithTokenCredentialWithoutVaultConfiguration_Throws()
        {
            // Arrange
            var authentication = Mock.Of<TokenCredential>();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(
                () => new KeyVaultSecretProvider(authentication, vaultConfiguration: null));
        }
    }
}
