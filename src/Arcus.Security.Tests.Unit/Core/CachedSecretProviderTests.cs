using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Interfaces;
using Arcus.Security.KeyVault;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Arcus.Security.Tests.Unit.KeyVault.Stubs;
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
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var memCache = new MemoryCache(new MemoryCacheOptions());

            // Act & Assert
            Assert.ThrowsAny<ArgumentNullException>(() => new CachedSecretProvider(null, TimeSpan.MaxValue, memCache));
        }

        [Fact]
        public void CachedSecretProvider_CreateWithNullCache_ShouldFailWithNullArgument()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);

            // Act & Assert
            Assert.ThrowsAny<ArgumentNullException>(() => new CachedSecretProvider(testSecretProvider, TimeSpan.MaxValue, null));
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

            // Act & Assert
            new CachedSecretProvider(testSecretProvider, TimeSpan.MaxValue);
        }

        [Fact]
        public void CachedSecretProvider_CreateWithCorrectArguments_ShouldSucceed()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());

            // Act & Assert
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, TimeSpan.MaxValue, memCache);
            Assert.NotNull(cachedSecretProvider);
        }

        [Fact]
        public async Task CachedSecretProvider_TwoCallsWithinCacheInterval_ShouldGetSameValueTwice()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());
            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, TimeSpan.FromSeconds(3), memCache);
            var firstValue = await cachedSecretProvider.Get(keyName);
            testSecretProvider.SecretValue = Guid.NewGuid().ToString("N"); // Change actual value on the internal secret provider !
            var secondValue = await cachedSecretProvider.Get(keyName);

            // Assert
            Assert.Equal(firstValue, secondValue);
            Assert.Equal(1, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_TwoCallsOutsideCacheInterval_ShouldGetDifferentValue()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());
            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, TimeSpan.FromMilliseconds(100), memCache);
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
        public async Task CachedSecretProvider_SkipCached_ShouldGetDifferentValue()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var memCache = new MemoryCache(new MemoryCacheOptions());
            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = new CachedSecretProvider(testSecretProvider, TimeSpan.FromMilliseconds(100), memCache);
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
    }
}
