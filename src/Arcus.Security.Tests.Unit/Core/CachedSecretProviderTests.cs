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

        [Fact]
        public async Task CachedSecretProvider_GetTwoSecretValues_WithinCacheInterval_ShouldReturnTheSameValues()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            var spyTestProvider = new TestSecretProviderStub(expectedFirstSecret);
            TimeSpan cacheInterval = TimeSpan.FromSeconds(3);

            const string keyName = "MyValue";
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(
                spyTestProvider,
                new CacheConfiguration(cacheInterval),
                new MemoryCache(new MemoryCacheOptions()));

            // Act
            string actualFirst = await cachedSecretProvider.Get(keyName);
            await Task.Delay(TimeSpan.Zero);
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = await cachedSecretProvider.Get(keyName);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedFirstSecret, actualSecond);
            Assert.Equal(1, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoSecretValues_OutsideCacheInterval_ShouldReturnDifferentValues()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            var spyTestProvider = new TestSecretProviderStub(expectedFirstSecret);
            TimeSpan cacheInterval = TimeSpan.FromMilliseconds(100);

            const string keyName = "MyValue";
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(
                spyTestProvider,
                new CacheConfiguration(cacheInterval),
                new MemoryCache(new MemoryCacheOptions()));

            // Act
            string actualFirst = await cachedSecretProvider.Get(keyName);
            await Task.Delay(TimeSpan.FromSeconds(1));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = await cachedSecretProvider.Get(keyName);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedSecondSecret, actualSecond);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoSecretValues_SkippedCache_ShouldReturnDifferentValues()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            var spyTestProvider = new TestSecretProviderStub(expectedFirstSecret);
            TimeSpan cacheInterval = TimeSpan.FromSeconds(3);

            const string keyName = "MyValue";
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(
                spyTestProvider,
                new CacheConfiguration(cacheInterval),
                new MemoryCache(new MemoryCacheOptions()));

            // Act
            string actualFirst = await cachedSecretProvider.Get(keyName, ignoreCache: true);
            await Task.Delay(TimeSpan.FromSeconds(1));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = await cachedSecretProvider.Get(keyName, ignoreCache: true);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedSecondSecret, actualSecond);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoRawSecrets_WithinCacheInterval_ShouldReturnTheSameValues()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            var spyTestProvider = new TestSecretProviderStub(expectedFirstSecret);
            TimeSpan cacheInterval = TimeSpan.FromSeconds(1);

            const string keyName = "MyValue";
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(
                spyTestProvider,
                new CacheConfiguration(cacheInterval),
                new MemoryCache(new MemoryCacheOptions()));

            // Act
            string actualFirst = await cachedSecretProvider.GetRawSecret(keyName);
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = await cachedSecretProvider.GetRawSecret(keyName);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedFirstSecret, actualSecond);
            Assert.Equal(1, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoRawSecrets_OutsideCacheInterval_ShouldReturnDifferentValues()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            var spyTestProvider = new TestSecretProviderStub(expectedFirstSecret);
            TimeSpan cacheInterval = TimeSpan.FromMilliseconds(100);

            const string keyName = "MyValue";
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(
                spyTestProvider,
                new CacheConfiguration(cacheInterval),
                new MemoryCache(new MemoryCacheOptions()));

            // Act
            string actualFirst = await cachedSecretProvider.GetRawSecret(keyName);
            await Task.Delay(TimeSpan.FromSeconds(1));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = await cachedSecretProvider.GetRawSecret(keyName);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedSecondSecret, actualSecond);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoRawSecrets_SkippedCache_ShouldReturnDifferentValues()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            var spyTestProvider = new TestSecretProviderStub(expectedFirstSecret);
            TimeSpan cacheInterval = TimeSpan.FromSeconds(3);

            const string keyName = "MyValue";
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(
                spyTestProvider,
                new CacheConfiguration(cacheInterval),
                new MemoryCache(new MemoryCacheOptions()));

            // Act
            string actualFirst = await cachedSecretProvider.GetRawSecret(keyName, ignoreCache: true);
            await Task.Delay(TimeSpan.FromSeconds(1));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = await cachedSecretProvider.GetRawSecret(keyName, ignoreCache: true);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedSecondSecret, actualSecond);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoSecrets_WithinCacheInterval_ShouldReturnTheSameValues()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            var spyTestProvider = new TestSecretProviderStub(expectedFirstSecret);
            TimeSpan cacheInterval = TimeSpan.FromSeconds(3);

            const string keyName = "MyValue";
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(
                spyTestProvider,
                new CacheConfiguration(cacheInterval),
                new MemoryCache(new MemoryCacheOptions()));

            // Act
            Secret actualFirst = await cachedSecretProvider.GetSecret(keyName);
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            Secret actualSecond = await cachedSecretProvider.GetSecret(keyName);

            // Assert
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst.Value);
            Assert.Equal(expectedFirstSecret, actualSecond.Value);
            Assert.Equal(1, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoSecrets_OutsideCacheInterval_ShouldReturnDifferentValues()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            var spyTestProvider = new TestSecretProviderStub(expectedFirstSecret);
            TimeSpan cacheInterval = TimeSpan.FromMilliseconds(100);

            const string keyName = "MyValue";
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(
                spyTestProvider,
                new CacheConfiguration(cacheInterval),
                new MemoryCache(new MemoryCacheOptions()));

            // Act
            Secret actualFirst = await cachedSecretProvider.GetSecret(keyName);
            await Task.Delay(TimeSpan.FromSeconds(1));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            Secret actualSecond = await cachedSecretProvider.GetSecret(keyName);

            // Assert
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst.Value);
            Assert.Equal(expectedSecondSecret, actualSecond.Value);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoSecrets_SkippedCache_ShouldReturnDifferentValues()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");

            var spyTestProvider = new TestSecretProviderStub(expectedFirstSecret);
            TimeSpan cacheInterval = TimeSpan.FromSeconds(3);

            const string keyName = "MyValue";
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(
                spyTestProvider,
                new CacheConfiguration(cacheInterval),
                new MemoryCache(new MemoryCacheOptions()));

            // Act
            Secret actualFirst = await cachedSecretProvider.GetSecret(keyName, ignoreCache: true);
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            Secret actualSecond = await cachedSecretProvider.GetSecret(keyName, ignoreCache: true);

            // Assert
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst.Value);
            Assert.Equal(expectedSecondSecret, actualSecond.Value);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }
    }
}
