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
            
            IHostBuilder builder = new HostBuilder();
            builder.ConfigureAppConfiguration(configBuilder =>
            {
                configBuilder.AddInMemoryCollection(new[]
                {
                    new KeyValuePair<string, string>(secretKey, expected)
                });
            });

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddConfiguration(config);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expected, provider.GetRawSecret(secretKey));
            Assert.Equal(expected, provider.GetSecret(secretKey).Value);
            Assert.Equal(expected, await provider.GetRawSecretAsync(secretKey));
            Assert.Equal(expected, (await provider.GetSecretAsync(secretKey)).Value);
        }

        [Fact]
        public async Task ConfigureSecretStore_AddConfigurationWithOptions_UsesIConfiguration()
        {
            // Arrange
            string secretKey = $"MySecret-{Guid.NewGuid()}";
            string expected = $"secret-{Guid.NewGuid()}";
            
            IHostBuilder builder = new HostBuilder();
            builder.ConfigureAppConfiguration(configBuilder =>
            {
                configBuilder.AddInMemoryCollection(new[]
                {
                    new KeyValuePair<string, string>(secretKey, expected)
                });
            });

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddConfiguration(config, name: "Some name", mutateSecretName: null);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Equal(expected, provider.GetRawSecret(secretKey));
            Assert.Equal(expected, provider.GetSecret(secretKey).Value);
            Assert.Equal(expected, await provider.GetRawSecretAsync(secretKey));
            Assert.Equal(expected, (await provider.GetSecretAsync(secretKey)).Value);
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

            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret("MySecret"));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret("MySecret"));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync("MySecret"));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync("MySecret"));
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEmptyConfigurationWithOptions_CantFindConfigKey()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddConfiguration(config, name: "Some name", mutateSecretName: null);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret("MySecret"));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret("MySecret"));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync("MySecret"));
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

            var secretName = "Arcus.ServicePrincipal.ClientId";
            Assert.Equal(expected, provider.GetRawSecret(secretName));
            Assert.Equal(expected, provider.GetSecret(secretName).Value);
            Assert.Equal(expected, await provider.GetRawSecretAsync(secretName));
            Assert.Equal(expected, (await provider.GetSecretAsync(secretName)).Value);
        }

        [Fact]
        public async Task ConfigureSecretStore_WithOptionsWithDotsToDoublePoints_FindsConfigKey()
        {
            // Arrange
            string expected = $"secret-{Guid.NewGuid()}";
            IHostBuilder builder = new HostBuilder();
            builder.ConfigureAppConfiguration(configBuilder =>
            {
                configBuilder.AddInMemoryCollection(new[]
                {
                    new KeyValuePair<string, string>("Arcus:ServicePrincipal:ClientId", expected)
                });
            });

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddConfiguration(config, mutateSecretName: name => name.Replace(".", ":"), name: null);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var secretName = "Arcus.ServicePrincipal.ClientId";
            Assert.Equal(expected, provider.GetRawSecret(secretName));
            Assert.Equal(expected, provider.GetSecret(secretName).Value);
            Assert.Equal(expected, await provider.GetRawSecretAsync(secretName));
            Assert.Equal(expected, (await provider.GetSecretAsync(secretName)).Value);
        }

        [Fact]
        public async Task ConfigureSecretStore_WithWrongMutation_DoesntFindConfigKey()
        {
            // Arrange
            var secretName = "Arcus:ServicePrincipal:ClientId";
            IHostBuilder builder = new HostBuilder()
                .ConfigureAppConfiguration(configBuilder =>
                {
                    configBuilder.AddInMemoryCollection(new[]
                    {
                        new KeyValuePair<string, string>(secretName, Guid.NewGuid().ToString())
                    });
                });

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddConfiguration(config, name => name.Replace(":", ".")));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(secretName));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(secretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(secretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretName));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithOptionsWithWrongMutation_DoesntFindConfigKey()
        {
            // Arrange
            IHostBuilder builder = new HostBuilder();
            var secretName = "Arcus:ServicePrincipal:ClientId";
            builder.ConfigureAppConfiguration(configBuilder =>
            {
                configBuilder.AddInMemoryCollection(new[]
                {
                    new KeyValuePair<string, string>(secretName, Guid.NewGuid().ToString())
                });
            });

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddConfiguration(config, mutateSecretName: name => name.Replace(":", "."), name: null);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(secretName));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(secretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(secretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretName));
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

        [Fact]
        public void ConfigureSecretStore_WithoutConfigurationWithOptions_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddConfiguration(configuration: null, name: "Some name", mutateSecretName: name => name);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public async Task GetSecretAsync_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            IConfiguration configuration = new ConfigurationBuilder().Build();
            var provider = new ConfigurationSecretProvider(configuration);

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.GetSecretAsync(secretName));
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public async Task GetRawSecretAsync_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            IConfiguration configuration = new ConfigurationBuilder().Build();
            var provider = new ConfigurationSecretProvider(configuration);

            // Act / Assert
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.GetRawSecretAsync(secretName));
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void GetSecret_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            IConfiguration configuration = new ConfigurationBuilder().Build();
            var provider = new ConfigurationSecretProvider(configuration);

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => provider.GetSecret(secretName));
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void GetRawSecret_WithoutSecretName_Throws(string secretName)
        {
            // Arrange
            IConfiguration configuration = new ConfigurationBuilder().Build();
            var provider = new ConfigurationSecretProvider(configuration);

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => provider.GetRawSecret(secretName));
        }

        [Fact]
        public void CreateProvider_WithoutConfiguration_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(() => new ConfigurationSecretProvider(configuration: null));
        }
    }
}
