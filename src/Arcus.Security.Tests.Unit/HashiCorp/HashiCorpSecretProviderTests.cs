using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Providers.HashiCorp.Configuration;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods.UserPass;
using Xunit;

namespace Arcus.Security.Tests.Unit.HashiCorp
{
    public class HashiCorpSecretProviderTests
    {
        [Fact]
        public void CreateProvider_WithoutSettings_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(
                () => new HashiCorpSecretProvider(settings: null, options: new HashiCorpVaultOptions(), secretPath: "secrets/path", logger: null));
        }

        [Fact]
        public void CreateProvider_WithoutSecretPaths_Throws()
        {
            var settings = new VaultClientSettings("https://vault.server:245", new UserPassAuthMethodInfo("username", "password"));
            Assert.ThrowsAny<ArgumentException>(
                () => new HashiCorpSecretProvider(settings, secretPath: null, options: new HashiCorpVaultOptions(), logger: null));
        }

        [Fact]
        public void CreateProvider_WithInvalidVaultUri_Throws()
        {
            var settings = new VaultClientSettings("not a valid vault URI", new UserPassAuthMethodInfo("username", "password"));
            Assert.ThrowsAny<ArgumentException>(
                () => new HashiCorpSecretProvider(settings, secretPath: "secret/path", options: new HashiCorpVaultOptions(), logger: null));
        }

        [Fact]
        public void CreateProvider_WithoutAuthenticationMethod_Throws()
        {
            var settings = new VaultClientSettings("https://vault.server:245", authMethodInfo: null);
            Assert.ThrowsAny<ArgumentException>(
                () => new HashiCorpSecretProvider(settings, secretPath: "secret/path", options: new HashiCorpVaultOptions(), logger: null));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("  ")]
        public async Task GetSecret_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            var provider = new HashiCorpSecretProvider(
                new VaultClientSettings("https://vault.server:246", new TokenAuthMethodInfo("vault.token")),
                secretPath: "secret/path",
                options: new HashiCorpVaultOptions { KeyValueVersion = VaultKeyValueSecretEngineVersion.V1 },
                logger: null);

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.GetSecretAsync(secretName));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("  ")]
        public async Task GetRawSecret_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            var provider = new HashiCorpSecretProvider(
                new VaultClientSettings("https://vault.server:246", new TokenAuthMethodInfo("vault.token")), 
                secretPath: "secret/path",
                options: new HashiCorpVaultOptions(),
                logger: null);

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.GetRawSecretAsync(secretName));
        }
    }
}
