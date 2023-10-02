using System;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.Dapr;
using Arcus.Security.Tests.Integration.Dapr.Hosting;
using Arcus.Security.Tests.Integration.Dapr.Resources.Local;
using Arcus.Security.Tests.Integration.KeyVault.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.Dapr
{
    public class DaprSecretProviderTests : IntegrationTest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DaprSecretProviderTests" /> class.
        /// </summary>
        public DaprSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        [Fact]
        public async Task Dapr_WithAzureKeyVault_Succeeds()
        {
            // Arrange
            KeyVaultConfig keyVaultConfig = Configuration.GetKeyVaultConfig();
            await using DaprSidecarFixture sideCar = await StartSideCarAsync(opt =>
            {
                opt.LoadKeyVault(keyVaultConfig);
            });

            ISecretProvider provider = sideCar.GetSecretProvider();
            Assert.NotNull(await provider.GetRawSecretAsync(keyVaultConfig.SecretName));
            Assert.NotNull((await provider.GetSecretAsync(keyVaultConfig.SecretName)).Value);
        }

        [Fact]
        public async Task Dapr_WithCustomMultiValuedLocal_Succeeds()
        {
            // Arrange
            var secretStore = JObject.Parse(@"{
                ""redisPassword"": ""your redis password"",
                ""connectionStrings"": {
                    ""mySql"": {
                        ""user"": ""your username"",
                        ""pass"": ""your password""
                    }
                }
            }");

            await using DaprSidecarFixture sideCar = await StartSideCarAsync(opt =>
            {
                opt.LoadSecrets(secretStore);
            });

            ISecretProvider provider = sideCar.GetSecretProvider((serviceProvider, secretOptions, fixtureOptions) =>
            {
                return new MultiValuedLocalDaprSecretProvider(
                    fixtureOptions.StoreName,
                    secretOptions,
                    serviceProvider.GetService<ILogger<DaprSecretProvider>>());
            });

            // Act
            string actual = await provider.GetRawSecretAsync("connectionStrings:mySql:pass");

            // Assert
            Assert.Equal("your password", actual);
        }

        [Fact]
        public async Task Dapr_WithKnownLocalSecretName_Succeeds()
        {
            // Arrange
            var secretStore = JObject.Parse(@"{
                ""redisPassword"": ""your redis password""
            }");

            await using DaprSidecarFixture sideCar = await StartSideCarAsync(opt =>
            {
                opt.LoadSecrets(secretStore);
            });

            ISecretProvider provider = sideCar.GetSecretProvider();

            // Act / Assert
            string secretName = "redisPassword";
            string expected = "your redis password";
            Assert.Equal(expected, await provider.GetRawSecretAsync(secretName));
            Assert.Equal(expected, (await provider.GetSecretAsync(secretName)).Value);
        }

        [Fact]
        public async Task Dapr_WithUnknownLocalSecretName_Fails()
        {
            // Arrange
            var secretStore = JObject.Parse(@"{
                ""redisPassword"": ""your redis password""
            }");

            await using DaprSidecarFixture sideCar = await StartSideCarAsync(opt =>
            {
                opt.LoadSecrets(secretStore);
            });

            ISecretProvider provider = sideCar.GetSecretProvider();

            // Act / Assert
            string secretName = "unknownPass";
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(secretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretName));
        }

        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 1)]
        public async Task Dapr_WithTrackDependency_Succeeds(bool trackDependency, int expectedDependencyTracked)
        {
            // Arrange
            await using DaprSidecarFixture sideCar = await StartSideCarAsync(opt =>
            {
                opt.LoadSecrets(JObject.Parse(@"{ ""myPass"": ""your password"" }"));
            });

            ISecretProvider provider = sideCar.GetSecretProvider(opt => opt.TrackDependency = trackDependency, SerilogLogger);

            // Act
            string actual = await provider.GetRawSecretAsync("myPass");

            // Assert
            Assert.Equal("your password", actual);
            Assert.Equal(expectedDependencyTracked, 
                InMemoryLogSink.CurrentLogEmits.Count(ev => ev.MessageTemplate.Text.Contains("Dependency")));
        }

        private async Task<DaprSidecarFixture> StartSideCarAsync(Action<DaprSidecarOptions> configureOptions)
        {
            return await DaprSidecarFixture.StartSideCarAsync(Configuration, Logger, configureOptions);
        }
    }
}
