using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Providers.HashiCorp.Configuration;
using Arcus.Security.Providers.HashiCorp.Extensions;
using Arcus.Security.Tests.Integration.HashiCorp.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.UserPass;
using Xunit;

namespace Arcus.Security.Tests.Integration.HashiCorp
{
    [Trait(name: "Category", value: "Integration")]
    public partial class HashiCorpSecretProviderTests : IntegrationTest
    {
        private const string DefaultDevMountPoint = "secret";

        /// <summary>
        /// Initializes a new instance of the <see cref="HashiCorpSecretProviderTests"/> class.
        /// </summary>
        public HashiCorpSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        private string UserPassUserName => Configuration["Arcus:HashiCorp:UserPass:UserName"];
        private string UserPassPassword => Configuration["Arcus:HashiCorp:UserPass:Password"];

        [Fact]
        public async Task AuthenticateWithUserPassKeyValueV2_GetSecret_Succeeds()
        {
            // Arrange
            string secretPath = "mysecret";
            string secretName = "my-value";
            string expected = "s3cr3t";

            using (HashiCorpVaultTestServer server = await StartServerWithUserPassAsync(DefaultDevMountPoint))
            {
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { [secretName] = expected });

                var authentication = new UserPassAuthMethodInfo(UserPassUserName, UserPassPassword);
                var settings = new VaultClientSettings(server.ListenAddress.ToString(), authentication);
                var provider = new HashiCorpSecretProvider(settings, secretPath, new HashiCorpVaultOptions 
                {
                    KeyValueMountPoint = DefaultDevMountPoint, 
                    KeyValueVersion = VaultKeyValueSecretEngineVersion.V2
                }, NullLogger<HashiCorpSecretProvider>.Instance);

                // Act
                string actual = await provider.GetRawSecretAsync(secretName);

                // Assert
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public async Task AuthenticateWithUserPassKeyValueV2_GetNotFoundSecret_Fails()
        {
            // Arrange
            string secretPath = "mysecret";
            string secretName = "my-value";
            string expected = "s3cr3t";

            using (HashiCorpVaultTestServer server = await StartServerWithUserPassAsync(DefaultDevMountPoint))
            {
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { ["unknown-prefix-" + secretName] = expected });

                var authentication = new UserPassAuthMethodInfo(UserPassUserName, UserPassPassword);
                var settings = new VaultClientSettings(server.ListenAddress.ToString(), authentication);
                var provider = new HashiCorpSecretProvider(settings, secretPath, new HashiCorpVaultOptions
                {
                    KeyValueMountPoint = DefaultDevMountPoint,
                    KeyValueVersion = VaultKeyValueSecretEngineVersion.V2
                },  NullLogger<HashiCorpSecretProvider>.Instance);

                // Act
                string actual = await provider.GetRawSecretAsync(secretName);

                // Assert
                Assert.Null(actual);
            }
        }

        [Fact]
        public async Task AddHashiCorpVaultWithUserPass_WithMutationToRemovePrefix_Succeeds()
        {
            // Arrange
            string secretPath = "secretpath";
            string secretKey = "my-value", expected = "s3cr3t";
            const string secretNamePrefix = "Test-";
            
            var builder = new HostBuilder();

            using (HashiCorpVaultTestServer server = await StartServerWithUserPassAsync(DefaultDevMountPoint))
            {
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { [secretKey] = expected });

                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddHashiCorpVaultWithUserPass(
                        server.ListenAddress.ToString(), UserPassUserName, UserPassPassword, secretPath,
                        configureOptions: options => options.KeyValueMountPoint = DefaultDevMountPoint, 
                        mutateSecretName: secretName => secretName.Remove(0, secretNamePrefix.Length),
                        name: null);
                });

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();
                string actual = await provider.GetRawSecretAsync(secretNamePrefix + secretKey);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public async Task AddHashiCorpVaultWithUserPass_WithWrongMutation_Fails()
        {
            // Arrange
            string secretPath = "secretpath";
            string secretKey = "my-value", expected = "s3cr3t";

            var builder = new HostBuilder();

            using (HashiCorpVaultTestServer server = await StartServerWithUserPassAsync(DefaultDevMountPoint))
            {
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { [secretKey] = expected });

                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddHashiCorpVaultWithUserPass(
                        server.ListenAddress.ToString(), UserPassUserName, UserPassPassword, secretPath,
                        configureOptions: options => options.KeyValueMountPoint = DefaultDevMountPoint,
                        mutateSecretName: secretName =>  "Test-" + secretName,
                        name: null);
                });

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretKey));
            }
        }

        [Fact]
        public async Task AddHashiCorpVault_WithMutationToRemovePrefix_Succeeds()
        {
            // Arrange
            string secretPath = "secretpath";
            string secretKey = "my-value", expected = "s3cr3t";
            const string secretNamePrefix = "Test-";
            
            var builder = new HostBuilder();

            using (HashiCorpVaultTestServer server = await StartServerWithUserPassAsync(DefaultDevMountPoint))
            {
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { [secretKey] = expected });

                var authentication = new UserPassAuthMethodInfo(UserPassUserName, UserPassPassword);
                var settings = new VaultClientSettings(server.ListenAddress.ToString(), authentication);

                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddHashiCorpVault(settings, secretPath,
                        options => options.KeyValueMountPoint = DefaultDevMountPoint, 
                        mutateSecretName: secretName => secretName.Remove(0, secretNamePrefix.Length),
                        name: null);
                });

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();
                string actual = await provider.GetRawSecretAsync(secretNamePrefix + secretKey);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public async Task AddHashiCorpVault_WithWrongMutation_Fails()
        {
            // Arrange
            string secretPath = "secretpath";
            string secretKey = "my-value", expected = "s3cr3t";

            var builder = new HostBuilder();

            using (HashiCorpVaultTestServer server = await StartServerWithUserPassAsync(DefaultDevMountPoint))
            {
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { [secretKey] = expected });

                var authentication = new UserPassAuthMethodInfo(UserPassUserName, UserPassPassword);
                var settings = new VaultClientSettings(server.ListenAddress.ToString(), authentication);

                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddHashiCorpVault(settings, secretPath, 
                        configureOptions: options => options.KeyValueMountPoint = DefaultDevMountPoint,
                        mutateSecretName: secretName => "Test-" + secretName,
                        name: null);
                });

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretKey));
            }
        }

        [Fact]
        public async Task AuthenticateWithUserPassKeyValueV1_GetSecret_Succeeds()
        {
            // Arrange
            string secretPath = "mysecret";
            string secretName = "my-value";
            string expected = "s3cr3t";

            const string mountPoint = "secret-v1";
            const VaultKeyValueSecretEngineVersion keyValueVersion = VaultKeyValueSecretEngineVersion.V1;

            using (HashiCorpVaultTestServer server = await StartServerWithUserPassAsync(mountPoint))
            {
                await server.MountKeyValueAsync(mountPoint, keyValueVersion);
                await server.KeyValueV1.WriteSecretAsync(
                    mountPoint: mountPoint,
                    path: secretPath,
                    values: new Dictionary<string, object> { [secretName] = expected });

                var authentication = new UserPassAuthMethodInfo(UserPassUserName, UserPassPassword);
                var settings = new VaultClientSettings(server.ListenAddress.ToString(), authentication);
                var provider = new HashiCorpSecretProvider(settings, secretPath, new HashiCorpVaultOptions
                {
                    KeyValueMountPoint = mountPoint, 
                    KeyValueVersion = keyValueVersion
                }, NullLogger<HashiCorpSecretProvider>.Instance);

                // Act
                string actual = await provider.GetRawSecretAsync(secretName);

                // Assert
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public async Task AuthenticateWithUserPassKeyValueV1_GetNotFoundSecret_Fails()
        {
            // Arrange
            string secretPath = "mysecret";
            string secretName = "my-value";
            string expected = "s3cr3t";

            const string mountPoint = "secret-v1";
            const VaultKeyValueSecretEngineVersion keyValueVersion = VaultKeyValueSecretEngineVersion.V1;

            using (HashiCorpVaultTestServer server = await StartServerWithUserPassAsync(mountPoint))
            {
                await server.MountKeyValueAsync(mountPoint, keyValueVersion);
                await server.KeyValueV1.WriteSecretAsync(
                    mountPoint: mountPoint,
                    path: secretPath,
                    values: new Dictionary<string, object> { ["unknown-prefix-" + secretName] = expected });

                var authentication = new UserPassAuthMethodInfo(UserPassUserName, UserPassPassword);
                var settings = new VaultClientSettings(server.ListenAddress.ToString(), authentication);
                var provider = new HashiCorpSecretProvider(settings, secretPath, new HashiCorpVaultOptions{
                    KeyValueMountPoint = mountPoint, 
                    KeyValueVersion = keyValueVersion
                }, NullLogger<HashiCorpSecretProvider>.Instance);

                // Act
                string actual = await provider.GetRawSecretAsync(secretName);

                // Assert
                Assert.Null(actual);
            }
        }

        private async Task<HashiCorpVaultTestServer> StartServerWithUserPassAsync(string availableSecretMountPoint)
        {
            const string policyName = "my-policy";

            var server = await HashiCorpVaultTestServer.StartServerAsync(Configuration, Logger);
            await server.AddPolicyAsync(policyName, availableSecretMountPoint, new[] { "read" });
            await server.EnableAuthenticationTypeAsync(AuthMethodDefaultPaths.UserPass, "Authenticating with username and password");
            await server.AddUserPassUserAsync(UserPassUserName, UserPassPassword, policyName);

            return server;
        }


    }
}
