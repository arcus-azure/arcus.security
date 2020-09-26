using System;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Xunit;

namespace Arcus.Security.Tests.Unit.KeyVault.Configuration
{
    public class KeyVaultConfigurationTests
    {
        [Fact]
        public void Constructor_UriWithoutVaultSuffix_Fails()
        {
            Assert.ThrowsAny<UriFormatException>(
                () => new KeyVaultConfiguration("https://something-without-azure-vault-suffix"));
        }

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
        public void Constructor_RawUriWithHttp_ThrowsUriFormatException()
        {
            // Arrange
            string vaultUri = $"http://{Guid.NewGuid():N}.vault.azure.net/";

            // Act & Assert
            Assert.Throws<UriFormatException>(() => new KeyVaultConfiguration(vaultUri));
        }

        [Fact]
        public void Constructor_UriWithHttp_ThrowsUriFormatException()
        {
            // Arrange
            string vaultUri = $"http://{Guid.NewGuid():N}.vault.azure.net/";
            var expectedVaultUri = new Uri(vaultUri);

            // Act & Assert
            Assert.Throws<UriFormatException>(() => new KeyVaultConfiguration(expectedVaultUri));
        }

        [Fact]
        public void Constructor_NoUriSpecified_ThrowsArgumentNullException()
        {
            // Arrange
            Uri vaultUri = null;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new KeyVaultConfiguration(vaultUri));
        }

        [Fact]
        public void Constructor_NoRawUriSpecified_ThrowsArgumentNullException()
        {
            // Arrange
            string rawVaultUri = null;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new KeyVaultConfiguration(rawVaultUri));
        }

        [Fact]
        public void Constructor_EmptyRawUriSpecified_ThrowsUriFormatException()
        {
            // Arrange
            string rawVaultUri = string.Empty;

            // Act & Assert
            Assert.Throws<UriFormatException>(() => new KeyVaultConfiguration(rawVaultUri));
        }

        [Fact]
        public void Constructor_RawUriWithSpaceSpecified_ThrowsUriFormatException()
        {
            // Arrange
            string rawVaultUri = " ";

            // Act & Assert
            Assert.Throws<System.UriFormatException>(() => new KeyVaultConfiguration(rawVaultUri));
        }
    }
}
