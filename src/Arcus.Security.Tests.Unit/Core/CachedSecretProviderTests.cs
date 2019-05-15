using System;
using System.Collections.Generic;
using System.Text;
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
            var cachedSecretProvider = new CachedSecretProvider(testSecretProvider);
        }

        [Fact]
        public void CachedSecretProvider_CreateWithoutCache_ShouldSucceed()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var cacheConfiguration = new CacheConfiguration(TimeSpan.MaxValue);

            // Act & Assert
            new CachedSecretProvider(testSecretProvider, cacheConfiguration);
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
        public async Task CachedSecretProvider_Get_TwoCallsWithinCacheInterval_ShouldGetSameValueTwice()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());
            var cacheConfiguration = new CacheConfiguration(TimeSpan.FromSeconds(3));
            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, cacheConfiguration, memCache);
            var firstValue = await cachedSecretProvider.Get(keyName);
            testSecretProvider.SecretValue = Guid.NewGuid().ToString("N"); // Change actual value on the internal secret provider !
            var secondValue = await cachedSecretProvider.Get(keyName);

            // Assert
            Assert.Equal(firstValue, secondValue);
            Assert.Equal(1, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetSecret_TwoCallsWithinCacheInterval_ShouldGetSameValueTwice()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());
            var cacheConfiguration = new CacheConfiguration(TimeSpan.FromSeconds(3));
            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, cacheConfiguration, memCache);
            var firstSecret = await cachedSecretProvider.GetSecret(keyName);
            testSecretProvider.SecretValue = Guid.NewGuid().ToString("N"); // Change actual value on the internal secret provider !
            var secondSecret = await cachedSecretProvider.GetSecret(keyName);

            // Assert
            Assert.Equal(firstSecret, secondSecret);
            Assert.Equal(1, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_Get_TwoCallsOutsideCacheInterval_ShouldGetDifferentValue()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());
            var cacheConfiguration = new CacheConfiguration(TimeSpan.FromMilliseconds(100));
            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, cacheConfiguration, memCache);
            var firstValue = await cachedSecretProvider.Get(keyName);
            await Task.Delay(TimeSpan.FromMilliseconds(150));
            string newSecretValue = Guid.NewGuid().ToString("N");
            testSecretProvider.SecretValue = newSecretValue; // Change actual value on the internal secret provider !
            var secondValue = await cachedSecretProvider.Get(keyName);

            // Assert
            Assert.Equal(secretKeyValue, firstValue);
            Assert.Equal(newSecretValue, secondValue);
            Assert.Equal(2, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetSecret_TwoCallsOutsideCacheInterval_ShouldGetDifferentValue()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());
            var cacheConfiguration = new CacheConfiguration(TimeSpan.FromMilliseconds(100));
            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, cacheConfiguration, memCache);
            Secret firstSecret = await cachedSecretProvider.GetSecret(keyName);
            await Task.Delay(TimeSpan.FromMilliseconds(150));
            string newSecretValue = Guid.NewGuid().ToString("N");
            testSecretProvider.SecretValue = newSecretValue; // Change actual value on the internal secret provider !
            Secret secondSecret = await cachedSecretProvider.GetSecret(keyName);

            // Assert
            Assert.True(firstSecret != null, "firstSecret != null");
            Assert.True(secondSecret != null, "secondSecret != null");

            Assert.Equal(secretKeyValue, firstSecret.Value);
            Assert.Equal(newSecretValue, secondSecret.Value);
            Assert.Equal(2, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_Get_SkipCached_ShouldGetDifferentValue()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());
            var cacheConfiguration = new CacheConfiguration(TimeSpan.FromMilliseconds(100));
            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, cacheConfiguration, memCache);
            var firstValue = await cachedSecretProvider.Get(keyName);
            await Task.Delay(TimeSpan.FromMilliseconds(150));
            string newSecretValue = Guid.NewGuid().ToString("N");
            testSecretProvider.SecretValue = newSecretValue; // Change actual value on the internal secret provider !
            var secondValue = await cachedSecretProvider.Get(keyName, true);

            // Assert
            Assert.Equal(secretKeyValue, firstValue);
            Assert.Equal(newSecretValue, secondValue);
            Assert.Equal(2, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetSecret_SkipCached_ShouldGetDifferentValue()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());
            var cacheConfiguration = new CacheConfiguration(TimeSpan.FromMilliseconds(100));
            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, cacheConfiguration, memCache);
            Secret firstSecret = await cachedSecretProvider.GetSecret(keyName);
            await Task.Delay(TimeSpan.FromMilliseconds(150));
            string newSecretValue = Guid.NewGuid().ToString("N");
            testSecretProvider.SecretValue = newSecretValue; // Change actual value on the internal secret provider !
            Secret secondSecret = await cachedSecretProvider.GetSecret(keyName, true);

            // Assert
            Assert.True(firstSecret != null, "firstSecret != null");
            Assert.True(secondSecret != null, "secondSecret != null");

            Assert.Equal(secretKeyValue, firstSecret.Value);
            Assert.Equal(newSecretValue, secondSecret.Value);
            Assert.Equal(2, testSecretProvider.CallsMadeSinceCreation);
        }
    }
}
