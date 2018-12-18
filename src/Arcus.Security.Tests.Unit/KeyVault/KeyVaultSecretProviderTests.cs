using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Core.Exceptions;
using Arcus.Security.KeyVault;
using Arcus.Security.KeyVault.Factories;
using Microsoft.Azure.KeyVault;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault
{
    public class KeyVaultSecretProviderTests
    {
        [Fact]
        public void KeyVaultSecretProvider_CreateWithEmptyArgument_ShouldFailWithargumentException()
        {
            // Arrange
            string uri = Guid.NewGuid().ToString("N");

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider(null, uri));
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider(null, null));
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider(new TestKeyVaultClientFactory(), null));
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultSecretProvider(new TestKeyVaultClientFactory(), string.Empty));
        }

        [Fact]
        public void KeyVaultSecretProvider_CreateWithValidArguments_ShouldSucceed()
        {
            // Arrange
            string uri = Guid.NewGuid().ToString("N");

            // Act & Assert
            var secretProvider = new KeyVaultSecretProvider(new TestKeyVaultClientFactory(), uri);
            Assert.NotNull(secretProvider);
        }

        private class TestKeyVaultClientFactory : KeyVaultClientFactory
        {
            public override Task<KeyVaultClient> CreateClient()
            {
                throw new NotImplementedException();
            }
        }
    }
}
