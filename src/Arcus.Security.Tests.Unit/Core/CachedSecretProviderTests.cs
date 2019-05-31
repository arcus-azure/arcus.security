using System;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Secrets.Core.Caching;
using Arcus.Security.Secrets.Core.Interfaces;
using Arcus.Security.Secrets.Core.Models;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.Caching.Memory;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class CachedSecretProviderTests
    {
        [Fact]
        public void CachedSecretProvider_CreateWithoutSecretProvider_ShouldFailWithArgumentNullException()
        {
            // Arrange
            var memCache = new MemoryCache(new MemoryCacheOptions());
            var cacheConfiguration = new CacheConfiguration(TimeSpan.MaxValue);

            // Act & Assert
            Assert.ThrowsAny<ArgumentNullException>(() => new CachedSecretProvider(null, cacheConfiguration, memCache));
        }

        [Fact]
        public void CachedSecretProvider_CreateWithNullCache_ShouldFailWithNullArgument()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var cacheConfiguration = new CacheConfiguration(TimeSpan.MaxValue);
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);

            // Act & Assert
            Assert.ThrowsAny<ArgumentNullException>(() => new CachedSecretProvider(testSecretProvider, cacheConfiguration, null));
        }

        [Fact]
        public void CachedSecretProvider_CreateWithOnlySecretProvider_ShouldSucceed()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);

            // Act & Assert
            var _ = new CachedSecretProvider(testSecretProvider);
        }

        [Fact]
        public void CachedSecretProvider_CreateWithoutCache_ShouldSucceed()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var cacheConfiguration = new CacheConfiguration(TimeSpan.MaxValue);

            // Act & Assert
            var _ = new CachedSecretProvider(testSecretProvider, cacheConfiguration);
        }

        [Fact]
        public void CachedSecretProvider_CreateWithCorrectArguments_ShouldSucceed()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());
            var cacheConfiguration = new CacheConfiguration(TimeSpan.MaxValue);

            // Act & Assert
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, cacheConfiguration, memCache);
            Assert.NotNull(cachedSecretProvider);
        }

        [Theory]
        [InlineData(GetCachedSecret.WithinCacheInterval)]
        [InlineData(GetCachedSecret.OutsideCacheInterval)]
        [InlineData(GetCachedSecret.SkippedCache)]
        public async Task CachedSecretProvider_GetTwoSecretValues_WithCaching(GetCachedSecret cacheSetup)
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            // Act 
            (string actualFirstSecret, string actualSecondSecret) = await GetTwoSecretsFromCachedProvider(
                (expectedFirstSecret, expectedSecondSecret),
                (provider, keyName) => provider.Get(keyName),
                cacheSetup);

            // Assert
            Assert.True(
                cacheSetup == GetCachedSecret.WithinCacheInterval 
                    == (actualFirstSecret == actualSecondSecret && expectedFirstSecret == actualFirstSecret),
                "Should get the same cached secret value when the two calls happen within the configured cache interval");

            Assert.True(
                (cacheSetup == GetCachedSecret.OutsideCacheInterval || cacheSetup == GetCachedSecret.SkippedCache) == 
                    (actualFirstSecret != actualSecondSecret
                     && expectedFirstSecret == actualFirstSecret
                     && expectedSecondSecret == actualSecondSecret),
                "Should get two different secret values when the second call happens outside the configured cache interval");
        }

        [Theory]
        [InlineData(GetCachedSecret.WithinCacheInterval)]
        [InlineData(GetCachedSecret.OutsideCacheInterval)]
        [InlineData(GetCachedSecret.SkippedCache)]
        public async Task CachedSecretProvider_GetTwoRawSecrets_WithCaching(GetCachedSecret cacheSetup)
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            // Act 
            (string actualFirstSecret, string actualSecondSecret) = await GetTwoSecretsFromCachedProvider(
                (expectedFirstSecret, expectedSecondSecret),
                (provider, keyName) => provider.GetRawSecret(keyName),
                cacheSetup);

            // Assert
            Assert.True(
                cacheSetup == GetCachedSecret.WithinCacheInterval 
                == (actualFirstSecret == actualSecondSecret && expectedFirstSecret == actualFirstSecret),
                "Should get the same cached secret value when the two calls happen within the configured cache interval");

            Assert.True(
                (cacheSetup == GetCachedSecret.OutsideCacheInterval || cacheSetup == GetCachedSecret.SkippedCache) 
                == (actualFirstSecret != actualSecondSecret
                    && expectedFirstSecret == actualFirstSecret
                    && expectedSecondSecret == actualSecondSecret),
                "Should get two different secret values when the second call happens outside the configured cache interval");
        }

        [Theory]
        [InlineData(GetCachedSecret.WithinCacheInterval)]
        [InlineData(GetCachedSecret.OutsideCacheInterval)]
        [InlineData(GetCachedSecret.SkippedCache)]
        public async Task CachedSecretProvider_GetTwoSecrets_WithCaching(GetCachedSecret cacheSetup)
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            // Act
            (Secret actualFirstSecret, Secret actualSecondSecret) = await GetTwoSecretsFromCachedProvider(
                (expectedFirstSecret, expectedSecondSecret),
                (provider, keyName) => provider.GetSecret(keyName),
                cacheSetup);

            // Assert
            Assert.True(actualFirstSecret != null, "actualFirstSecret != null");
            Assert.True(actualSecondSecret != null, "actualSecondSecret != null");
            
            Assert.True(
                cacheSetup == GetCachedSecret.WithinCacheInterval 
                == (actualFirstSecret.Value == actualSecondSecret.Value 
                    && expectedFirstSecret == actualFirstSecret.Value),
                "Should get the same cached secret value when the two calls happen within the configured cache interval");
            
            Assert.True(
                (cacheSetup == GetCachedSecret.OutsideCacheInterval || cacheSetup == GetCachedSecret.SkippedCache) == 
                (actualFirstSecret != actualSecondSecret
                 && expectedFirstSecret == actualFirstSecret.Value
                 && expectedSecondSecret == actualSecondSecret.Value),
                "Should get two different secret values when the second call happens outside the configured cache interval");
        }

        [Theory]
        [InlineData(GetCachedSecret.WithinCacheInterval)]
        [InlineData(GetCachedSecret.OutsideCacheInterval)]
        [InlineData(GetCachedSecret.SkippedCache)]
        public async Task CachedSecretProvider_GetTwoSecrets_WithIgnoredCaching(GetCachedSecret cacheSetup)
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            // Act
            (Secret actualFirstSecret, Secret actualSecondSecret) = await GetTwoSecretsFromCachedProvider(
                (expectedFirstSecret, expectedSecondSecret),
                (provider, keyName) => provider.GetSecret(keyName, ignoreCache: true),
                cacheSetup,
                ignoreCache: true);

            // Assert
            Assert.True(actualFirstSecret != null, "actualFirstSecret != null");
            Assert.True(actualSecondSecret != null, "actualSecondSecret != null");
            Assert.True(
                actualFirstSecret != actualSecondSecret
                && expectedFirstSecret == actualFirstSecret.Value
                && expectedSecondSecret == actualSecondSecret.Value,
                "Should get two different secret values when no caching is configured (ignoreCache = true)");
        }

        public enum GetCachedSecret { SkippedCache = 1, WithinCacheInterval = 2, OutsideCacheInterval = 4 }

        private static async Task<(T, T)> GetTwoSecretsFromCachedProvider<T>(
            (string, string) expectedSecretValues,
            Func<ICachedSecretProvider, string, Task<T>> getSecret,
            GetCachedSecret cacheSetup,
            bool ignoreCache = false)
        {
            string firstSecretValue = expectedSecretValues.Item1;
            var testSecretProvider = new TestSecretProviderStub(firstSecretValue);

            (TimeSpan cacheInterval, TimeSpan secondCallDelay) =
                cacheSetup == GetCachedSecret.OutsideCacheInterval
                    ? (TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(150))
                    : cacheSetup == GetCachedSecret.WithinCacheInterval
                        ? (TimeSpan.FromSeconds(3), TimeSpan.Zero)
                        : (TimeSpan.FromTicks(1), TimeSpan.Zero);

            const string keyName = "MyValue";
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(
                testSecretProvider,
                new CacheConfiguration(cacheInterval),
                new MemoryCache(new MemoryCacheOptions()));
            
            // Act: change actual value on the internal secret provider !
            T firstSecret = await getSecret(cachedSecretProvider, keyName);
            await Task.Delay(secondCallDelay);

            testSecretProvider.SecretValue = expectedSecretValues.Item2; 
            T secondSecret = await getSecret(cachedSecretProvider, keyName);

            // Assert
            Assert.True(
                (cacheSetup == GetCachedSecret.WithinCacheInterval && !ignoreCache) 
                == (1 == testSecretProvider.CallsMadeSinceCreation),
                "Stub secret provider should be called only once when the second call happens within the configured cache interval");
            Assert.True(
                (cacheSetup == GetCachedSecret.OutsideCacheInterval 
                 || cacheSetup == GetCachedSecret.SkippedCache
                 || ignoreCache)
                == (2 == testSecretProvider.CallsMadeSinceCreation),
                "Stub secret provider should be called two times when the second call happens outside the configured cache interval");

            return (firstSecret, secondSecret);
        }
    }
}
