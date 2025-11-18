using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core.Providers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Integration.Core
{
    public class ConfigurationSecretProviderTests : IntegrationTest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationSecretProviderTests"/> class.
        /// </summary>
        public ConfigurationSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        [Fact]
        public async Task GetSecret_WithAvailableApplicationConfigurationValue_SucceedsByFindingSecret()
        {
            // Arrange
            var configSecret = GivenNewAppConfigSecret();

            await using var store = GivenSecretStore(
                host => host.ConfigureAppConfiguration((_, config) =>
                {
                    config.AddInMemoryCollection([configSecret]);
                }),
                (config, store) =>
                {
                    // Act
                    WhenConfigurationFor(store, config);
                });

            // Assert
            store.ShouldFindProvider<ConfigurationSecretProvider>();
            await store.ShouldFindSecretAsync(configSecret.Key, configSecret.Value);
        }

        private static KeyValuePair<string, string> GivenNewAppConfigSecret()
        {
            return new KeyValuePair<string, string>(Bogus.Random.Guid().ToString(), Bogus.Random.Guid().ToString());
        }

        private void WhenConfigurationFor(SecretStoreBuilder store, IConfiguration config)
        {
            store.AddConfiguration(config, ConfigureOptions);
        }
    }
}
