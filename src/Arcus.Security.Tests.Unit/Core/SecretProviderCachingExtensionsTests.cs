using Arcus.Security.Core.Caching;
using Arcus.Security.Tests.Unit.Core.Stubs;
using System;
using System.Threading.Tasks;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class SecretProviderCachingExtensionsTests
    {
        [Fact]
        public async Task SecretProviderCachingExtensions_TwoCallsWithinCacheInterval_ShouldGetSameValueTwice()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);
            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = testSecretProvider.WithCaching(TimeSpan.FromSeconds(3));
            var firstValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            testSecretProvider.SecretValue = Guid.NewGuid().ToString("N"); // Change actual value on the internal secret provider !
            var secondValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            
            // Assert
            Assert.Equal(firstValue, secondValue);
            Assert.Equal(1, testSecretProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task SecretProviderCachingExtensions_TwoCallsOutsideCacheInterval_ShouldGetDifferentValue()
        {
            // Arrange
            string secretKeyValue = Guid.NewGuid().ToString("N");
            var testSecretProvider = new TestSecretProviderStub(secretKeyValue);

            string keyName = "MyValue";

            // Act 
            ICachedSecretProvider cachedSecretProvider = testSecretProvider.WithCaching(TimeSpan.FromMilliseconds(100));
            var firstValue = await cachedSecretProvider.GetRawSecretAsync(keyName);
            await Task.Delay(TimeSpan.FromMilliseconds(150));
            string newSecretValue = Guid.NewGuid().ToString("N");
            testSecretProvider.SecretValue = newSecretValue; // Change actual value on the internal secret provider !
            var secondValue = await cachedSecretProvider.GetRawSecretAsync(keyName);

            // Assert
            Assert.Equal(secretKeyValue, firstValue);
            Assert.Equal(newSecretValue, secondValue);
            Assert.Equal(2, testSecretProvider.CallsMadeSinceCreation);
        }
    }
}
