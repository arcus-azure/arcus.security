using System;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault.Configuration
{
    public class KeyVaultConfigurationTests
    {
        [Fact]
        public void Constructor_ValidRawUri_Succeeds()
        {
            // Arrange
            string vaultUri = $"https://{Guid.NewGuid().ToString("N").Substring(0, 24)}.vault.azure.net/";
            var expectedVaultUri = new Uri(vaultUri);

            // Act
            var keyVaultConfiguration = new KeyVaultConfiguration(vaultUri);

            // Assert
            Assert.NotNull(keyVaultConfiguration);
            Assert.Equal(expectedVaultUri, keyVaultConfiguration.VaultUri);
        }

        [Fact]
        public void Constructor_ValidUri_Succeeds()
        {
            // Arrange
            var expectedVaultUri = new Uri($"https://{Guid.NewGuid().ToString("N").Substring(0, 24)}.vault.azure.net/");

            // Act
            var keyVaultConfiguration = new KeyVaultConfiguration(expectedVaultUri);

            // Assert
            Assert.NotNull(keyVaultConfiguration);
            Assert.Equal(expectedVaultUri, keyVaultConfiguration.VaultUri);
        }

        [Fact]
        public void Constructor_NoUriSpecified_ThrowsArgumentNullException()
        {
            // Arrange
            Uri vaultUri = null;

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultConfiguration(vaultUri));
        }

        [Fact]
        public void Constructor_NoRawUriSpecified_ThrowsArgumentNullException()
        {
            // Arrange
            string rawVaultUri = null;

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultConfiguration(rawVaultUri));
        }

        [Fact]
        public void Constructor_EmptyRawUriSpecified_ThrowsUriFormatException()
        {
            // Arrange
            string rawVaultUri = string.Empty;

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultConfiguration(rawVaultUri));
        }

        [Fact]
        public void Constructor_RawUriWithSpaceSpecified_ThrowsUriFormatException()
        {
            // Arrange
            string rawVaultUri = " ";

            // Act & Assert
            Assert.ThrowsAny<ArgumentException>(() => new KeyVaultConfiguration(rawVaultUri));
        }
    }
}
