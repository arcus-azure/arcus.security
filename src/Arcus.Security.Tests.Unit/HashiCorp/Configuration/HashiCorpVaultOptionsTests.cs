using System;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Providers.HashiCorp.Configuration;
using Xunit;

namespace Arcus.Security.Tests.Unit.HashiCorp.Configuration
{
    public class HashiCorpVaultOptionsTests
    {
        [Fact]
        public void SetSecretEngineVersion_WithOutOfBoundsVersion_Throws()
        {
            // Arrange
            var options = new HashiCorpVaultOptions();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(
                () => options.KeyValueVersion = VaultKeyValueSecretEngineVersion.V1 | VaultKeyValueSecretEngineVersion.V2);
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void SetMountPoint_WithBlankValue_Throws(string mountPoint)
        {
            // Arrange
            var options = new HashiCorpVaultOptions();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.KeyValueMountPoint = mountPoint);
        }
    }
}