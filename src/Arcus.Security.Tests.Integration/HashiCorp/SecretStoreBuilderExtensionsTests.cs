using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.HashiCorp.Extensions;
using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Security.Tests.Integration.HashiCorp.Hosting;
using Arcus.Testing.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.HashiCorp
{
    [Trait(name: "Category", value: "Integration")]
    public class SecretStoreBuilderExtensionsTests : IntegrationTest
    {
        private const string DefaultDevMountPoint = "secret";

        private readonly TestConfig _config;
        private readonly XunitTestLogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreBuilderExtensionsTests"/> class.
        /// </summary>
        public SecretStoreBuilderExtensionsTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
            _config = TestConfig.Create();
            _logger = new XunitTestLogger(outputWriter);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task AuthenticateWithInvalidUserPassPasswordKeyValue_GetSecret_Fails(bool trackDependency)
        {
            // Arrange
            string secretPath = "mysecret";
            string secretName = "my-value";
            string expected = "s3cr3t";

            string userName = _config["Arcus:HashiCorp:UserPass:UserName"];
            string password = _config["Arcus:HashiCorp:UserPass:Password"];
            string invalidPassword = Guid.NewGuid().ToString();

            const string policyName = "my-policy";

            var builder = new HostBuilder();
            builder.UseSerilog(Logger);

            using (var server = await HashiCorpVaultTestServer.StartServerAsync(_config, _logger))
            {
                await server.AddPolicyAsync(policyName, DefaultDevMountPoint, new[] { "read" });
                await server.EnableAuthenticationTypeAsync(AuthMethodDefaultPaths.UserPass, "Authenticating with username and password");
                await server.AddUserPassUserAsync(userName, password, policyName);
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { [secretName] = expected });

                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddHashiCorpVaultWithUserPass(server.ListenAddress.ToString(), userName, invalidPassword, secretPath, options =>
                    {
                        options.KeyValueMountPoint = secretPath;
                        options.TrackDependency = trackDependency;
                    });
                });

                // Assert
                using (IHost host = builder.Build())
                {
                    var provider = host.Services.GetRequiredService<ISecretProvider>();
                    var exception = await Assert.ThrowsAsync<VaultApiException>(() => provider.GetRawSecretAsync(secretName));
                    Assert.Equal(HttpStatusCode.BadRequest, exception.HttpStatusCode);
                }

                AssertTrackedHashiCorpVaultDependency(trackDependency);
            }
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task AuthenticateWithUnauthorizedUserPassUserKeyValue_GetSecret_Fails(bool trackDependency)
        {
            // Arrange
            string secretPath = "mysecret";
            string secretName = "my-value";
            string expected = "s3cr3t";

            string userName = _config["Arcus:HashiCorp:UserPass:UserName"];
            string password = _config["Arcus:HashiCorp:UserPass:Password"];

            const string policyName = "my-policy";

            var builder = new HostBuilder();
            builder.UseSerilog(Logger);

            using (var server = await HashiCorpVaultTestServer.StartServerAsync(_config, _logger))
            {
                await server.EnableAuthenticationTypeAsync(AuthMethodDefaultPaths.UserPass, "Authenticating with username and password");
                await server.AddUserPassUserAsync(userName, password, policyName);
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { [secretName] = expected });

                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddHashiCorpVaultWithUserPass(server.ListenAddress.ToString(), userName, password, secretPath, options =>
                    {
                        options.KeyValueMountPoint = secretPath;
                        options.TrackDependency = trackDependency;
                    });
                });

                // Assert
                using (IHost host = builder.Build())
                {
                    var provider = host.Services.GetRequiredService<ISecretProvider>();
                    
                    var exceptionFromSecret = await Assert.ThrowsAsync<VaultApiException>(() => provider.GetSecretAsync(secretName));
                    var exceptionFromRawSecret = await Assert.ThrowsAsync<VaultApiException>(() => provider.GetRawSecretAsync(secretName));
                    Assert.Equal(HttpStatusCode.Forbidden, exceptionFromSecret.HttpStatusCode);
                    Assert.Equal(HttpStatusCode.Forbidden, exceptionFromRawSecret.HttpStatusCode);
                }

                AssertTrackedHashiCorpVaultDependency(trackDependency);
            }
        }

        private void AssertTrackedHashiCorpVaultDependency(bool trackDependency)
        {
            var expectedTrackedDependencyCount = Convert.ToInt16(trackDependency);
            int actualTrackedDependencyCount = InMemoryLogSink.LogEvents.Count(ev => ev.MessageTemplate.Text.Contains("Dependency"));
            
            Assert.Equal(expectedTrackedDependencyCount, actualTrackedDependencyCount);
        }
    }
}
