using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Providers.HashiCorp.Extensions;
using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Security.Tests.Integration.HashiCorp.Hosting;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Integration.HashiCorp
{
    public class HashiCorpSecretProviderTests : IntegrationTest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HashiCorpSecretProviderTests"/> class.
        /// </summary>
        public HashiCorpSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        [Theory]
        [InlineData(VaultKeyValueSecretEngineVersion.V1)]
        [InlineData(VaultKeyValueSecretEngineVersion.V2)]
        public async Task GetSecret_WithAvailableHashiCorpVaultSecret_SucceedsByFindingSecret(VaultKeyValueSecretEngineVersion version)
        {
            // Arrange
            string secretPath = Bogus.Lorem.Word().ToLowerInvariant();
            string secretName = Bogus.Lorem.Word().ToLowerInvariant();
            string secretValue = Bogus.Random.Guid().ToString();

            using var vault = await GivenNewHashiCorpVaultSecretAsync(secretName, secretValue, secretPath, version);

            await using var store = GivenSecretStore(store =>
            {
                // Act
                store.AddHashiCorpVault(vault.Client.Settings, secretPath, options =>
                {
                    options.KeyValueMountPoint = GetMountPoint(version);
                    options.KeyValueVersion = version;

                    ConfigureOptions(options);
                });
            });

            // Assert
            store.ShouldFindProvider<HashiCorpSecretProvider>();
            await store.ShouldFindSecretAsync(secretName, secretValue);
        }

        private new SecretStoreTestContext GivenSecretStore(Action<SecretStoreBuilder> configureStore)
        {
            var context = base.GivenSecretStore(configureStore);
            context.SupportSynchronous = false;

            return context;
        }

        private async Task<HashiCorpVaultTestServer> GivenNewHashiCorpVaultSecretAsync(
            string secretName,
            string secretValue,
            string secretPath,
            VaultKeyValueSecretEngineVersion version)
        {
            var vault = await HashiCorpVaultTestServer.StartServerAsync(Configuration, Logger);
            string mountPoint = GetMountPoint(version);

            switch (version)
            {
                case VaultKeyValueSecretEngineVersion.V1:
                    await vault.MountKeyValueAsync(mountPoint, version);
                    await vault.KeyValueV1.WriteSecretAsync(
                        mountPoint: mountPoint,
                        path: secretPath,
                        values: new Dictionary<string, object> { [secretName] = secretValue });
                    break;

                case VaultKeyValueSecretEngineVersion.V2:
                    await vault.AddPolicyAsync(Bogus.Lorem.Word().ToLowerInvariant(), mountPoint, ["read"]);
                    await vault.KeyValueV2.WriteSecretAsync(
                        mountPoint: mountPoint,
                        path: secretPath,
                        data: new Dictionary<string, object> { [secretName] = secretValue });
                    break;
            }

            return vault;
        }

        private static string GetMountPoint(VaultKeyValueSecretEngineVersion version)
        {
            return version switch
            {
                VaultKeyValueSecretEngineVersion.V1 => "secret-v1",
                VaultKeyValueSecretEngineVersion.V2 => "secret"
            };
        }
    }
}
