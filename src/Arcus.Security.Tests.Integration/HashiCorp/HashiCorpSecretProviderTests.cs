using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Security.Tests.Integration.HashiCorp.Hosting;
using Arcus.Testing.Logging;
using Microsoft.Extensions.Logging;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.UserPass;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.HashiCorp
{
    [Trait(name: "Category", value: "Integration")]
    public class HashiCorpSecretProviderTests
    {
        private const string DefaultDevMountPoint = "secret";

        private readonly TestConfig _config;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="HashiCorpSecretProviderTests"/> class.
        /// </summary>
        public HashiCorpSecretProviderTests(ITestOutputHelper outputWriter)
        {
            _config = TestConfig.Create();
            _logger = new XunitTestLogger(outputWriter);
        }

        [Fact]
        public async Task AuthenticateWithUserPassKeyValueV2_GetSecret_Succeeds()
        {
            // Arrange
            string secretPath = "mysecret";
            string secretName = "my-value";
            string expected = "s3cr3t";

            string userName = "arcus";
            string password = "123";

            const string policyName = "my-policy";

            using (var server = await HashiCorpVaultTestServer.StartServerAsync(_config, _logger))
            {
                await server.AddPolicyAsync(policyName, DefaultDevMountPoint, new[] { "read" });
                await server.EnableAuthenticationTypeAsync(AuthMethodDefaultPaths.UserPass, "Authenticating with username and password");
                await server.AddUserPassUserAsync(userName, password, policyName);
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { [secretName] = expected });

                var authentication = new UserPassAuthMethodInfo(userName, password);
                var settings = new VaultClientSettings(server.ListenAddress.ToString(), authentication);
                var provider = new HashiCorpSecretProvider(settings, VaultKeyValueSecretEngineVersion.V2, DefaultDevMountPoint, secretPath);

                // Act
                string actual = await provider.GetRawSecretAsync(secretName);

                // Assert
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public async Task AuthenticateWithUserPassKeyValueV1_GetSecret_Succeeds()
        {
            // Arrange
            string secretPath = "mysecret";
            string secretName = "my-value";
            string expected = "s3cr3t";

            string userName = "arcus";
            string password = "123";

            const string policyName = "my-policy";
            const string mountPoint = "secret-v1";
            const VaultKeyValueSecretEngineVersion keyValueVersion = VaultKeyValueSecretEngineVersion.V1;

            using (var server = await HashiCorpVaultTestServer.StartServerAsync(_config, _logger))
            {
                await server.MountKeyValueAsync(mountPoint, keyValueVersion);
                await server.AddPolicyAsync(policyName, mountPoint, new[] { "read" });
                await server.EnableAuthenticationTypeAsync(AuthMethodDefaultPaths.UserPass, "Authenticating with username and password");
                await server.AddUserPassUserAsync(userName, password, policyName);
                await server.KeyValueV1.WriteSecretAsync(
                    mountPoint: mountPoint,
                    path: secretPath,
                    values: new Dictionary<string, object> { [secretName] = expected });

                var authentication = new UserPassAuthMethodInfo(userName, password);
                var settings = new VaultClientSettings(server.ListenAddress.ToString(), authentication);
                var provider = new HashiCorpSecretProvider(settings, keyValueVersion, mountPoint, secretPath);

                // Act
                string actual = await provider.GetRawSecretAsync(secretName);

                // Assert
                Assert.Equal(expected, actual);
            }
        }
    }
}
