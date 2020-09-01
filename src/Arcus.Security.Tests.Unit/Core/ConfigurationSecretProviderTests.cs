using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Providers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class ConfigurationSecretProviderTests
    {
        [Fact]
        public async Task ConfigureSecretStore_AddConfiguration_UsesIConfiguration()
        {
            // Arrange
            string secretKey = $"MySecret-{Guid.NewGuid()}";
            string expected = $"secret-{Guid.NewGuid()}";
            
            IHostBuilder builder = new HostBuilder()
                .ConfigureAppConfiguration(configBuilder => configBuilder.AddInMemoryCollection(new[]
                {
                    new KeyValuePair<string, string>(secretKey, expected)
                }));

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddConfiguration(config));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            string actual = await provider.GetRawSecretAsync(secretKey);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEmptyConfiguration_CantFindConfigKey()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddConfiguration(config));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync("MySecret"));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithDotsToDoublePoints_FindsConfigKey()
        {
            // Arrange
            string expected = $"secret-{Guid.NewGuid()}";
            IHostBuilder builder = new HostBuilder()
                .ConfigureAppConfiguration(configBuilder => configBuilder.AddInMemoryCollection(new[]
                {
                    new KeyValuePair<string, string>("Arcus:ServicePrincipal:ClientId", expected)
                }));

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddConfiguration(config, name => name.Replace(".", ":")));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Arcus.ServicePrincipal.ClientId");
            Assert.Equal(expected, secret.Value);
        }

        [Fact]
        public async Task ConfigureSecretStore_WithWrongMutation_DoesntFindConfigKey()
        {
            // Arrange
            IHostBuilder builder = new HostBuilder()
                .ConfigureAppConfiguration(configBuilder => configBuilder.AddInMemoryCollection(new[]
                {
                    new KeyValuePair<string, string>("Arcus:ServicePrincipal:ClientId", Guid.NewGuid().ToString())
                }));

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddConfiguration(config, name => name.Replace(":", ".")));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync("Arcus:ServicePrincipal:ClientId"));
        }

        [Fact]
        public void ConfigureSecretStore_WithoutConfiguration_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddConfiguration(configuration: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("  ")]
        public async Task GetSecret_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            IConfiguration configuration = new ConfigurationBuilder().Build();
            var provider = new ConfigurationSecretProvider(configuration);

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
            IConfiguration configuration = new ConfigurationBuilder().Build();
            var provider = new ConfigurationSecretProvider(configuration);

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.GetRawSecretAsync(secretName));
        }

        [Fact]
        public void CreateProvider_WithoutConfiguration_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(() => new ConfigurationSecretProvider(configuration: null));
        }
    }
}
