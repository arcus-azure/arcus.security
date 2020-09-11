﻿using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using Xunit.Sdk;

namespace Arcus.Security.Tests.Unit.Core
{
    public class IHostBuilderExtensionsTests
    {
        [Fact]
        public void ConfigureSecretStore_WithoutFoundLazySecretProvider_ThrowsException()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(serviceProvider => null));

            // Assert
            IHost host = builder.Build();
            Assert.Throws<InvalidOperationException>(() => host.Services.GetService<ISecretProvider>());
        }

        [Fact]
        public void ConfigureSecretStore_WithFailedLazySecretProviderCreation_ThrowsException()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(serviceProvider => throw new TestClassException("Some failure"));
            });

            // Assert
            IHost host = builder.Build();
            Assert.Throws<TestClassException>(() => host.Services.GetService<ISecretProvider>());
        }

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
        public async Task ConfigureSecretStore_WithFoundLazyCachedSecretProvider_UsesLazyRegisteredSecretProvider()
        {
            // Arrange
            string expected = $"secret-{Guid.NewGuid()}";
            var stubProvider = new TestSecretProviderStub(expected);

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(serviceProvider => stubProvider));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            string actual = await provider.GetRawSecretAsync("ignored-key");
            Assert.Equal(expected, actual);
            Assert.Equal(1, stubProvider.CallsMadeSinceCreation);
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
        public async Task ConfigureSecretStore_AddMultipleLazySecretProviders_UsesAllSecretProviders()
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
                stores.AddProvider(serviceProvider => stubProvider2);
            }).ConfigureSecretStore((config, stores) => stores.AddProvider(serviceProvider => stubProvider3));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue1, await provider.GetRawSecretAsync(secretKey1));
            Assert.Equal(secretValue2, await provider.GetRawSecretAsync(secretKey2));
            Assert.Equal(secretValue3, await provider.GetRawSecretAsync(secretKey3));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithoutCachingProviderWithMutation_DoesntFindCachedProvider()
        {
            // Arrange
            var stubProvider = new InMemorySecretProvider(("Arcus.KeyVault.Secret", Guid.NewGuid().ToString()));
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider, secretName => "Arcus." + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var cachedSecretProvider = host.Services.GetRequiredService<ICachedSecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => cachedSecretProvider.GetSecretAsync("KeyVault.Secret", ignoreCache: false));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithCachingProviderWithMutation_DoesFindCachedProvider()
        {
            // Arrange
            var expected = Guid.NewGuid().ToString();
            var stubProvider = new InMemoryCachedSecretProvider(("Arcus.KeyVault.Secret", expected));
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider, secretName => "Arcus." + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var cachedSecretProvider = host.Services.GetRequiredService<ICachedSecretProvider>();
            Secret secret = await cachedSecretProvider.GetSecretAsync("KeyVault.Secret", ignoreCache: false);
            Assert.Equal(expected, secret.Value);
        }

        [Fact]
        public async Task ConfigureSecretStore_WithLazySecretProviderWithMutation_DoesntFindCachedProvider()
        {
            // Arrange
            var stubProvider = new InMemorySecretProvider(("Arcus.KeyVault.Secret", Guid.NewGuid().ToString()));
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(serviceProvider => stubProvider, secretName => "Arcus." + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var cachedSecretProvider = host.Services.GetRequiredService<ICachedSecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => cachedSecretProvider.GetSecretAsync("KeyVault.Secret", ignoreCache: false));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithLazyCachedSecretProvider_FindsInvalidateSecret()
        {
            // Arrange
            var secretKey = "Arcus.KeyVault.Secret";
            var expected = Guid.NewGuid().ToString();
            var stubProvider = new InMemoryCachedSecretProvider((secretKey, expected));
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(serviceProvider => stubProvider);
            });

            // Assert
            IHost host = builder.Build();
            var cachedSecretProvider = host.Services.GetRequiredService<ICachedSecretProvider>();
            Secret secret = await cachedSecretProvider.GetSecretAsync(secretKey, ignoreCache: false);
            Assert.Equal(expected, secret.Value);
        }
    }
}
