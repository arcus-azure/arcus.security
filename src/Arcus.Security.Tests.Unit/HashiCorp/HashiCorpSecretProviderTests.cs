﻿using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.HashiCorp;
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
                () => new HashiCorpSecretProvider(settings: null, secretEngineVersion: VaultKeyValueSecretEngineVersion.V2, mountPoint: "kv-v2", secretPath: "secrets/path"));
        }

        [Fact]
        public void CreateProvider_WithOutOfBoundsClientApiVersion_Throws()
        {
            var settings = new VaultClientSettings("https://vault.server:245", new UserPassAuthMethodInfo("username", "password"));
            Assert.ThrowsAny<ArgumentException>(
                () => new HashiCorpSecretProvider(settings, VaultKeyValueSecretEngineVersion.V1 | VaultKeyValueSecretEngineVersion.V2, "kv-v2", "secret/path"));
        }

        [Fact]
        public void CreateProvider_WithoutSecretPaths_Throws()
        {
            var settings = new VaultClientSettings("https://vault.server:245", new UserPassAuthMethodInfo("username", "password"));
            Assert.ThrowsAny<ArgumentException>(
                () => new HashiCorpSecretProvider(settings, VaultKeyValueSecretEngineVersion.V1, mountPoint:"kv-v2", secretPath: null));
        }

        [Fact]
        public void CreateProvider_WithoutMountPoint_Throws()
        {
            var settings = new VaultClientSettings("https://vault.server:245", new UserPassAuthMethodInfo("username", "password"));
            Assert.ThrowsAny<ArgumentException>(
                () => new HashiCorpSecretProvider(settings, VaultKeyValueSecretEngineVersion.V2, mountPoint: null, secretPath: "secret/path"));
        }

        [Fact]
        public void CreateProvider_WithInvalidVaultUri_Throws()
        {
            var settings = new VaultClientSettings("not a valid vault URI", new UserPassAuthMethodInfo("username", "password"));
            Assert.ThrowsAny<ArgumentException>(
                () => new HashiCorpSecretProvider(settings, VaultKeyValueSecretEngineVersion.V1, mountPoint: "kv-v2", secretPath: "secret/path"));
        }

        [Fact]
        public void CreateProvider_WithoutAuthenticationMethod_Throws()
        {
            var settings = new VaultClientSettings("https://vault.server:245", authMethodInfo: null);
            Assert.ThrowsAny<ArgumentException>(
                () => new HashiCorpSecretProvider(settings, VaultKeyValueSecretEngineVersion.V1, mountPoint: "kv-v2", secretPath: "secret/path"));
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
                mountPoint: "secret",
                secretPath: "secret/path",
                secretEngineVersion: VaultKeyValueSecretEngineVersion.V1);

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
                mountPoint: "secret",
                secretPath: "secret/path",
                secretEngineVersion: VaultKeyValueSecretEngineVersion.V2);

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.GetRawSecretAsync(secretName));
        }
    }
}
