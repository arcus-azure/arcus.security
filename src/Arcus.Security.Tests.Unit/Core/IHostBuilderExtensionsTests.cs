using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class IHostBuilderExtensionsTests
    {
        [Fact]
        public async Task ConfigureSecretStore_WithoutSecretProviders_ThrowsException()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => { });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync("ignored-key"));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithoutFoundSecretProvider_ThrowsException()
        {
            // Arrange
            var builder = new HostBuilder();
            var emptyProvider = new InMemorySecretProvider();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(emptyProvider));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync("ignored-key"));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithoutFoundCachedProvider_ThrowsException()
        {
            // Arrange
            const string secretKey = "MySecret";
            var stubProvider = new InMemorySecretProvider((secretKey, $"secret-{Guid.NewGuid()}"));

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.InvalidateSecretAsync(secretKey));
        }

        [Fact]
        public async Task ConfigureSecretStore_AddInMemorySecretProvider_UsesInMemorySecretsInSecretStore()
        {
            // Arrange
            const string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider((secretKey, secretValue));
            
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue, await provider.GetRawSecretAsync(secretKey));
            Assert.NotNull(host.Services.GetService<ICachedSecretProvider>());
        }

        [Fact]
        public async Task ConfigureSecretStore_WithCachingDuration_RegistersCachingSecretProvider()
        {
            // Arrange
            string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider((secretKey, secretValue));
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider)
                      .WithCaching(TimeSpan.FromSeconds(5));
            });

            // Assert
            IHost host = builder.Build();
            Assert.NotNull(host.Services.GetService<ISecretProvider>());
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            Assert.Equal(secretValue, await provider.GetRawSecretAsync(secretKey, ignoreCache: false));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithCachingDurationAndMemoryCache_RegistersCachingSecretProvider()
        {
            // Arrange
            string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider((secretKey, secretValue));

            var builder = new HostBuilder();
            var duration = TimeSpan.FromSeconds(5);
            var memoryCache = new MemoryCache(new MemoryCacheOptions());

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider).WithCaching(duration, memoryCache));

            // Assert
            IHost host = builder.Build();
            Assert.NotNull(host.Services.GetService<ISecretProvider>());
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            Assert.Equal(secretValue, await provider.GetRawSecretAsync(secretKey));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithCaching_RegistersCachingSecretProvider()
        {
            // Arrange
            string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider((secretKey, secretValue));

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider).WithCaching());

            // Assert
            IHost host = builder.Build();
            Assert.NotNull(host.Services.GetService<ISecretProvider>());
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            Assert.Equal(secretValue, await provider.GetRawSecretAsync(secretKey));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithCachingConfiguration_RegistersCachingSecretProvider()
        {
            // Arrange
            string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider((secretKey, secretValue));

            var builder = new HostBuilder();
            var configuration = new CacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider).WithCaching(configuration));

            // Assert
            IHost host = builder.Build();
            Assert.NotNull(host.Services.GetService<ISecretProvider>());
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            Assert.Equal(secretValue, await provider.GetRawSecretAsync(secretKey));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithCachingConfigurationAndMemoryCache_RegistersCachingSecretProvider()
        {
            // Arrange
            string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider((secretKey, secretValue));

            var builder = new HostBuilder();
            var configuration = new CacheConfiguration();
            var memoryCache = new MemoryCache(new MemoryCacheOptions());

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider).WithCaching(configuration, memoryCache));

            // Assert
            IHost host = builder.Build();
            Assert.NotNull(host.Services.GetService<ISecretProvider>());
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            Assert.Equal(secretValue, await provider.GetRawSecretAsync(secretKey));
        }

        [Fact]
        public async Task ConfigureSecretStore_AddMultipleSecretProviders_UsesAllSecretStores()
        {
            // Arrange
            string secretKey1 = "MySecret1";
            string secretValue1 = $"secret-{Guid.NewGuid()}";
            var stubProvider1 = new InMemorySecretProvider((secretKey1, secretValue1));
            
            string secretKey2 = "MySecret2";
            string secretValue2 = $"secret-{Guid.NewGuid()}";
            var stubProvider2 = new InMemorySecretProvider((secretKey2, secretValue2));

            string secretKey3 = "MySecret3";
            string secretValue3 = $"secret-{Guid.NewGuid()}";
            var stubProvider3 = new InMemorySecretProvider((secretKey3, secretValue3));

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((context, config, stores) =>
            {
                stores.AddProvider(stubProvider1);
                stores.AddProvider(stubProvider2);
            }).ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider3));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue1, await provider.GetRawSecretAsync(secretKey1));
            Assert.Equal(secretValue2, await provider.GetRawSecretAsync(secretKey2));
            Assert.Equal(secretValue3, await provider.GetRawSecretAsync(secretKey3));
        }

        [Fact]
        public async Task ConfigureSecretStore_AddCachedSecretProvider_InvalidatesSecret()
        {
            // Arrange
            string secretKey = "MySecret";
            var spyProvider = new Mock<ICachedSecretProvider>();
            spyProvider.Setup(store => store.GetSecretAsync(secretKey))
                       .ReturnsAsync(new Secret($"secret-{Guid.NewGuid()}"));

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((context, stores) => stores.AddCachedProvider(spyProvider.Object));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            await provider.InvalidateSecretAsync(secretKey);
            spyProvider.Verify(store => store.InvalidateSecretAsync(secretKey), Times.Once);
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariables_UsesEnvironmentVariableSecrets()
        {
            // Arrange
            string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";

            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create(secretKey, secretValue))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) => stores.AddEnvironmentVariables());

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();
                Assert.Equal(secretValue, await provider.GetRawSecretAsync(secretKey));
            }
        }
    }
}
