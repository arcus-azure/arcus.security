using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Testing;
using Arcus.Testing.Security.Providers.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core.Extensions
{
    // ReSharper disable once InconsistentNaming
    public class IServiceCollectionExtensionsTests
    {
        [Fact]
        public async Task AddSecretStore_AddMultipleSecretProviders_UsesAllSecretStores()
        {
            // Arrange
            string secretKey1 = "MySecret1";
            string secretValue1 = $"secret-{Guid.NewGuid()}";
            var stubProvider1 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey1] = secretValue1 });

            string secretKey2 = "MySecret2";
            string secretValue2 = $"secret-{Guid.NewGuid()}";
            var stubProvider2 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey2] = secretValue2 });

            string secretKey3 = "MySecret3";
            string secretValue3 = $"secret-{Guid.NewGuid()}";
            var stubProvider3 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey3] = secretValue3 });

            var services = new ServiceCollection();

            // Act
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(stubProvider1);
                stores.AddProvider(stubProvider2);
            }).AddSecretStore(stores => stores.AddProvider(stubProvider3));

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue1, await secretProvider.GetRawSecretAsync(secretKey1));
            Assert.Equal(secretValue2, await secretProvider.GetRawSecretAsync(secretKey2));
            Assert.Equal(secretValue3, await secretProvider.GetRawSecretAsync(secretKey3));
            Assert.NotNull(serviceProvider.GetRequiredService<ICachedSecretProvider>());
        }

        [Fact]
        public async Task AddSecretStore_AddMultipleLazySecretProviders_UsesAllSecretProviders()
        {
            // Arrange
            string secretKey1 = "MySecret1";
            string secretValue1 = $"secret-{Guid.NewGuid()}";
            var stubProvider1 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey1] = secretValue1 });

            string secretKey2 = "MySecret2";
            string secretValue2 = $"secret-{Guid.NewGuid()}";
            var stubProvider2 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey2] = secretValue2 });

            string secretKey3 = "MySecret3";
            string secretValue3 = $"secret-{Guid.NewGuid()}";
            var stubProvider3 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey3] = secretValue3 });

            var services = new ServiceCollection();

            // Act
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(stubProvider1);
                stores.AddProvider(provider => stubProvider2);
            }).AddSecretStore(stores => stores.AddProvider(provider => stubProvider3));

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue1, await secretProvider.GetRawSecretAsync(secretKey1));
            Assert.Equal(secretValue2, await secretProvider.GetRawSecretAsync(secretKey2));
            Assert.Equal(secretValue3, await secretProvider.GetRawSecretAsync(secretKey3));
            Assert.NotNull(serviceProvider.GetRequiredService<ICachedSecretProvider>());
        }

        [Fact]
        public async Task AddSecretStore_WithLazyCachedSecretProvider_FindsInvalidateSecret()
        {
            // Arrange
            var secretKey = "Arcus.KeyVault.Secret";
            var expected = Guid.NewGuid().ToString();
            var stubProvider = new InMemoryCachedSecretProvider(new Dictionary<string, string> { [secretKey] = expected });
            var services = new ServiceCollection();

            // Act
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(provider => stubProvider);
            });

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var cachedSecretProvider = serviceProvider.GetRequiredService<ICachedSecretProvider>();
            Secret secret = await cachedSecretProvider.GetSecretAsync(secretKey, ignoreCache: false);
            Assert.Equal(expected, secret.Value);
        }

        [Fact]
        public async Task AddSecretStore_WithLogger_UsesLogger()
        {
            // Arrange
            var services = new ServiceCollection();
            var spyLogger = new InMemoryLogger();
            services.AddLogging(logging => logging.SetMinimumLevel(LogLevel.Trace)
                                                  .AddProvider(new CustomLoggerProvider(spyLogger)));

            const string secretName = "MySecret";
            var stubProvider = new InMemorySecretProvider(new Dictionary<string, string> { [secretName] = $"secret-{Guid.NewGuid()}" });

            // Act
            services.AddSecretStore(stores => stores.AddProvider(stubProvider));

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            await secretProvider.GetRawSecretAsync(secretName);
            Assert.NotEmpty(spyLogger.Messages);
        }

        [Fact]
        public void AddSecretStore_WithoutExceptionFilter_Throws()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => services.AddSecretStore(stores =>
            {
                stores.AddCriticalException<AuthenticationException>(exceptionFilter: null);
            }));
        }

        [Fact]
        public void AddSecretStore_WithoutSecretProvider_Fails()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act / Assert
            Assert.ThrowsAny<ArgumentNullException>(() => services.AddSecretStore(stores => stores.AddProvider(secretProvider: null)));
        }

        [Fact]
        public void AddSecretStore_WithoutLazySecretProvider_Fails()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddSecretStore(stores => stores.AddProvider(serviceProvider => null));

            // Assert
            IServiceProvider provider = services.BuildServiceProvider();
            Assert.ThrowsAny<InvalidOperationException>(() => provider.GetRequiredService<ISecretProvider>());
        }

        [Fact]
        public void AddSecretStore_WithoutConfigureSecretStoresFunction_Fails()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => services.AddSecretStore(configureSecretStores: null));
        }
    }
}
