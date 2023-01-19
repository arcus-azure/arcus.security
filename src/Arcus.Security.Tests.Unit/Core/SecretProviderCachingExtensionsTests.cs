using Arcus.Security.Core.Caching;
using Arcus.Security.Tests.Unit.Core.Stubs;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class SecretProviderCachingExtensionsTests
    {
        [Fact]
        public async Task WithCachingTimeSpanMemoryCache_TwoCallsWithinCacheInterval_ShouldGetSameValueTwice()
        {
            // Arrange
            var secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var keyName = "MyValue";
            var cache = new MemoryCache(Options.Create(new MemoryCacheOptions()));
            
            // Act 
            ICachedSecretProvider cachedSecretProvider = testSecretProvider.WithCaching(TimeSpan.FromSeconds(3), cache);
            string firstValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            
            ChangeInternalCachedSecret(testSecretProvider);
            string secondValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            
            // Assert
            Assert.Equal(firstValue, secondValue);
            Assert.Equal(1, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task WithCachingTimeSpanMemoryCache_TwoCallsOutsideCacheInterval_ShouldGetDifferentValue()
        {
            // Arrange
            var secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var keyName = "MyValue";
            var cache = new MemoryCache(Options.Create(new MemoryCacheOptions()));

            // Act 
            ICachedSecretProvider cachedSecretProvider = testSecretProvider.WithCaching(TimeSpan.FromMilliseconds(100), cache);
            string firstValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            
            await Task.Delay(TimeSpan.FromMilliseconds(150));
            string newSecretValue = Guid.NewGuid().ToString("N");
            ChangeInternalCachedSecret(testSecretProvider, newSecretValue);
            string secondValue = await cachedSecretProvider.GetRawSecretAsync(keyName);

            // Assert
            Assert.Equal(secretKeyValue, firstValue);
            Assert.Equal(newSecretValue, secondValue);
            Assert.Equal(2, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task WithCachingTimeSpan_TwoCallsWithinCacheInterval_ShouldGetSameValueTwice()
        {
            // Arrange
            var secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = testSecretProvider.WithCaching(TimeSpan.FromSeconds(3));
            string firstValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            
            ChangeInternalCachedSecret(testSecretProvider);
            string secondValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            
            // Assert
            Assert.Equal(firstValue, secondValue);
            Assert.Equal(1, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task WithCachingTimeSpan_TwoCallsOutsideCacheInterval_ShouldGetDifferentValue()
        {
            // Arrange
            var secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = testSecretProvider.WithCaching(TimeSpan.FromMilliseconds(100));
            string firstValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            
            await Task.Delay(TimeSpan.FromMilliseconds(150));
            string newSecretValue = Guid.NewGuid().ToString("N");
            ChangeInternalCachedSecret(testSecretProvider, newSecretValue);
            string secondValue = await cachedSecretProvider.GetRawSecretAsync(keyName);

            // Assert
            Assert.Equal(secretKeyValue, firstValue);
            Assert.Equal(newSecretValue, secondValue);
            Assert.Equal(2, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task WithCachingDefault_TwoCallsWithinCacheInterval_ShouldGetSameValueTwice()
        {
            // Arrange
            var secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            var keyName = "MyValue";
            
            // Act 
            ICachedSecretProvider cachedSecretProvider = testSecretProvider.WithCaching();
            string firstValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            
            ChangeInternalCachedSecret(testSecretProvider);
            string secondValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            
            // Assert
            Assert.Equal(firstValue, secondValue);
            Assert.Equal(1, testSecretProvider.CallsMadeSinceCreation);
        }

        private static void ChangeInternalCachedSecret(TestSecretProviderStub testSecretProvider)
        {
            ChangeInternalCachedSecret(testSecretProvider, Guid.NewGuid().ToString("N"));
        }

        private static void ChangeInternalCachedSecret(TestSecretProviderStub testSecretProvider, string secretValue)
        {
            testSecretProvider.SecretValue = secretValue;
        }
    }
}
