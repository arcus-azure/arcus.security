using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.HashiCorp.Extensions;
using Arcus.Security.Tests.Integration.HashiCorp.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods;
using Xunit;

namespace Arcus.Security.Tests.Integration.HashiCorp
{
    public partial class DeprecatedHashiCorpSecretProviderTests
    {
        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 2)]
        public async Task AuthenticateWithInvalidUserPassPasswordKeyValue_GetSecret_Fails(bool trackDependency, int expectedTrackedDependencies)
        {
            // Arrange
            string secretPath = "mysecret";
            string secretName = "my-value";
            string expected = "s3cr3t";

            string invalidPassword = Guid.NewGuid().ToString();

            const string policyName = "my-policy";

            var builder = new HostBuilder();
            builder.UseSerilog(SerilogLogger);

            using (var server = await HashiCorpVaultTestServer.StartServerAsync(Configuration, Logger))
            {
                await server.AddPolicyAsync(policyName, DefaultDevMountPoint, new[] { "read" });
                await server.EnableAuthenticationTypeAsync(AuthMethodDefaultPaths.UserPass, "Authenticating with username and password");
                await server.AddUserPassUserAsync(UserPassUserName, UserPassPassword, policyName);
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { [secretName] = expected });

                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddHashiCorpVaultWithUserPass(server.ListenAddress.ToString(), UserPassUserName, invalidPassword, secretPath, options =>
                    {
                        options.KeyValueMountPoint = secretPath;
                        options.TrackDependency = trackDependency;
                    });
                });

                // Assert
                using (IHost host = builder.Build())
                {
                    var provider = host.Services.GetRequiredService<ISecretProvider>();
                    var exceptionFromSecret = await Assert.ThrowsAsync<VaultApiException>(async () => { Secret _ = await provider.GetSecretAsync(secretName); });
                    var exceptionFromRawSecret = await Assert.ThrowsAsync<VaultApiException>(() => provider.GetRawSecretAsync(secretName));
                    Assert.Equal(HttpStatusCode.BadRequest, exceptionFromSecret.HttpStatusCode);
                    Assert.Equal(HttpStatusCode.BadRequest, exceptionFromRawSecret.HttpStatusCode);
                }

                AssertTrackedHashiCorpVaultDependency(expectedTrackedDependencies);
            }
        }

        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 2)]
        public async Task AuthenticateWithUnauthorizedUserPassUserKeyValue_GetSecret_Fails(bool trackDependency, int expectedTrackedDependencies)
        {
            // Arrange
            string secretPath = "mysecret";
            string secretName = "my-value";
            string expected = "s3cr3t";

            const string policyName = "my-policy";

            var builder = new HostBuilder();
            builder.UseSerilog(SerilogLogger);

            using (var server = await HashiCorpVaultTestServer.StartServerAsync(Configuration, Logger))
            {
                await server.EnableAuthenticationTypeAsync(AuthMethodDefaultPaths.UserPass, "Authenticating with username and password");
                await server.AddUserPassUserAsync(UserPassUserName, UserPassPassword, policyName);
                await server.KeyValueV2.WriteSecretAsync(
                    mountPoint: DefaultDevMountPoint,
                    path: secretPath,
                    data: new Dictionary<string, object> { [secretName] = expected });

                // Act
                builder.ConfigureSecretStore((config, stores) =>
                {
                    stores.AddHashiCorpVaultWithUserPass(server.ListenAddress.ToString(), UserPassUserName, UserPassPassword, secretPath, options =>
                    {
                        options.KeyValueMountPoint = secretPath;
                        options.TrackDependency = trackDependency;
                    });
                });

                // Assert
                using (IHost host = builder.Build())
                {
                    var provider = host.Services.GetRequiredService<ISecretProvider>();

                    var exceptionFromSecret = await Assert.ThrowsAsync<VaultApiException>(async () => { Secret _ = await provider.GetSecretAsync(secretName); });
                    var exceptionFromRawSecret = await Assert.ThrowsAsync<VaultApiException>(() => provider.GetRawSecretAsync(secretName));
                    Assert.Equal(HttpStatusCode.Forbidden, exceptionFromSecret.HttpStatusCode);
                    Assert.Equal(HttpStatusCode.Forbidden, exceptionFromRawSecret.HttpStatusCode);
                }

                AssertTrackedHashiCorpVaultDependency(expectedTrackedDependencies);
            }
        }

        private void AssertTrackedHashiCorpVaultDependency(int expectedTrackedDependencyCount)
        {
            int actualTrackedDependencyCount = InMemoryLogSink.CurrentLogEmits.Count(ev => ev.MessageTemplate.Text.Contains("Dependency"));
            Assert.Equal(expectedTrackedDependencyCount, actualTrackedDependencyCount);
        }
    }
}
