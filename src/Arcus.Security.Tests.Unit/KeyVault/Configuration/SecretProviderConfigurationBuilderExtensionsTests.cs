using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Xunit;
using Arcus.Security.Tests.Unit.Core.Stubs;

namespace Arcus.Security.Tests.Unit.KeyVault.Configuration
{
    public class SecretProviderConfigurationBuilderExtensionsTests
    {
        [Fact]
        public void AddAzureKeyVault_WithSecretWithConfigurationKey_AccessesSecretProviderForSecretValuesFromConfigurationTokens_ResolvesConfigurationToken()
        {
            // Arrange
            const string configurationKey = "Connection_String";
            const string expected = "connection to somewhere";

            var stubProvider = new InMemorySecretProvider((configurationKey, expected));

            var configuration =
                new ConfigurationBuilder()
                    .AddInMemoryCollection(new [] { new KeyValuePair<string, string>("ConnectionString", $"#{{{configurationKey}}}#") })
                    .AddAzureKeyVault(stubProvider)
                    .Build();

            // Act
            IConfigurationSection section = configuration.GetSection(configurationKey);

            // Assert
            Assert.Equal(expected, section.Value);
        }

        [Fact]
        public void AddAzureKeyVault_WithoutSecretWithConfigurationKey_AccessesSecretProviderForSecretValuesFromConfigurationTokens_ButDontResolveConfigurationToken()
        {
            // Arrange
            const string configurationKey = "ConnectionString";
            const string configurationToken = "#{ConnectionString}#";

            var stubProvider = new InMemorySecretProvider(("Some other secret key name", "Some other secret value"));

            var configuration =
                new ConfigurationBuilder()
                    .AddInMemoryCollection(new [] { new KeyValuePair<string, string>(configurationKey, configurationToken) })
                    .AddAzureKeyVault(stubProvider)
                    .Build();

            // Act
            IConfigurationSection section = configuration.GetSection(configurationKey);

            // Assert
            Assert.Equal(configurationToken, section.Value);
        }
    }
}
