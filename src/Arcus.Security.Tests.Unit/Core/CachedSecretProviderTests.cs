using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Bogus;
using Microsoft.Extensions.Caching.Memory;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class CachedSecretProviderTests
    {
        private static readonly Faker BogusGenerator = new Faker();

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
        public async Task CachedSecretProvider_GetTwoRawSecretsAsync_WithinCacheInterval_ShouldReturnTheSameValues()
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
            string actualFirst = await cachedSecretProvider.GetRawSecretAsync(keyName);
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = await cachedSecretProvider.GetRawSecretAsync(keyName);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedFirstSecret, actualSecond);
            Assert.Equal(1, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public void CachedSecretProvider_GetTwoRawSecrets_WithinCacheInterval_ShouldReturnTheSameValues()
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
            string actualFirst = cachedSecretProvider.GetRawSecret(keyName);
            Thread.Sleep(TimeSpan.FromMilliseconds(100));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = cachedSecretProvider.GetRawSecret(keyName);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedFirstSecret, actualSecond);
            Assert.Equal(1, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoRawSecretsAsync_OutsideCacheInterval_ShouldReturnDifferentValues()
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
            string actualFirst = await cachedSecretProvider.GetRawSecretAsync(keyName);
            await Task.Delay(TimeSpan.FromSeconds(1));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = await cachedSecretProvider.GetRawSecretAsync(keyName);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedSecondSecret, actualSecond);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public void CachedSecretProvider_GetTwoRawSecrets_OutsideCacheInterval_ShouldReturnDifferentValues()
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
            string actualFirst = cachedSecretProvider.GetRawSecret(keyName);
            Thread.Sleep(TimeSpan.FromSeconds(1));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = cachedSecretProvider.GetRawSecret(keyName);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedSecondSecret, actualSecond);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoRawSecretsAsync_SkippedCache_ShouldReturnDifferentValues()
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
            string actualFirst = await cachedSecretProvider.GetRawSecretAsync(keyName, ignoreCache: true);
            await Task.Delay(TimeSpan.FromSeconds(1));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            string actualSecond = await cachedSecretProvider.GetRawSecretAsync(keyName, ignoreCache: true);

            // Assert
            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedSecondSecret, actualSecond);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoSecretsAsync_WithinCacheInterval_ShouldReturnTheSameValues()
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
            Secret actualFirst = await cachedSecretProvider.GetSecretAsync(keyName);
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            Secret actualSecond = await cachedSecretProvider.GetSecretAsync(keyName);

            // Assert
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst.Value);
            Assert.Equal(expectedFirstSecret, actualSecond.Value);
            Assert.Equal(1, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public void CachedSecretProvider_GetTwoSecrets_WithinCacheInterval_ShouldReturnTheSameValues()
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
            Secret actualFirst = cachedSecretProvider.GetSecret(keyName);
            Thread.Sleep(TimeSpan.FromMilliseconds(100));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            Secret actualSecond = cachedSecretProvider.GetSecret(keyName);

            // Assert
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst.Value);
            Assert.Equal(expectedFirstSecret, actualSecond.Value);
            Assert.Equal(1, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoSecretsAsync_OutsideCacheInterval_ShouldReturnDifferentValues()
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
            Secret actualFirst = await cachedSecretProvider.GetSecretAsync(keyName);
            await Task.Delay(TimeSpan.FromSeconds(1));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            Secret actualSecond = await cachedSecretProvider.GetSecretAsync(keyName);

            // Assert
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst.Value);
            Assert.Equal(expectedSecondSecret, actualSecond.Value);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public void CachedSecretProvider_GetTwoSecrets_OutsideCacheInterval_ShouldReturnDifferentValues()
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
            Secret actualFirst = cachedSecretProvider.GetSecret(keyName);
            Thread.Sleep(TimeSpan.FromSeconds(1));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            Secret actualSecond = cachedSecretProvider.GetSecret(keyName);

            // Assert
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst.Value);
            Assert.Equal(expectedSecondSecret, actualSecond.Value);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CachedSecretProvider_GetTwoSecretsAsync_SkippedCache_ShouldReturnDifferentValues()
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
            Secret actualFirst = await cachedSecretProvider.GetSecretAsync(keyName, ignoreCache: true);
            await Task.Delay(TimeSpan.FromMilliseconds(100));
            spyTestProvider.SecretValue = expectedSecondSecret; 
            Secret actualSecond = await cachedSecretProvider.GetSecretAsync(keyName, ignoreCache: true);

            // Assert
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst.Value);
            Assert.Equal(expectedSecondSecret, actualSecond.Value);
            Assert.Equal(2, spyTestProvider.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CacheSecretProvider_GetRawSecretAsync_InvalidateSecret_ShouldRequestNewSecretEvenWithinCacheDuration()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");
            var testProviderStub = new TestSecretProviderStub(expectedFirstSecret);
            var cacheInterval = TimeSpan.FromSeconds(10);

            const string keyName = "MySecret";
            var cachedSecretProvider = new CachedSecretProvider(
                testProviderStub,
                new CacheConfiguration(cacheInterval));

            string actualFirst = await cachedSecretProvider.GetRawSecretAsync(keyName);
            testProviderStub.SecretValue = expectedSecondSecret;

            // Act
            await cachedSecretProvider.InvalidateSecretAsync(keyName);

            // Assert
            string actualSecond = await cachedSecretProvider.GetRawSecretAsync(keyName);
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedSecondSecret, actualSecond);
            Assert.Equal(2, testProviderStub.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CacheSecretProvider_GetRawSecret_InvalidateSecret_ShouldRequestNewSecretEvenWithinCacheDuration()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");
            var testProviderStub = new TestSecretProviderStub(expectedFirstSecret);
            var cacheInterval = TimeSpan.FromSeconds(10);

            const string keyName = "MySecret";
            var cachedSecretProvider = new CachedSecretProvider(
                testProviderStub,
                new CacheConfiguration(cacheInterval));

            string actualFirst = cachedSecretProvider.GetRawSecret(keyName);
            testProviderStub.SecretValue = expectedSecondSecret;

            // Act
            await cachedSecretProvider.InvalidateSecretAsync(keyName);

            // Assert
            string actualSecond = cachedSecretProvider.GetRawSecret(keyName);
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst);
            Assert.Equal(expectedSecondSecret, actualSecond);
            Assert.Equal(2, testProviderStub.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CacheSecretProvider_GetSecretAsync_InvalidateSecret_ShouldRequestNewSecretEvenWithinCacheDuration()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");
            var testProviderStub = new TestSecretProviderStub(expectedFirstSecret);
            var cacheInterval = TimeSpan.FromSeconds(10);

            const string keyName = "MySecret";
            var cachedSecretProvider = new CachedSecretProvider(
                testProviderStub,
                new CacheConfiguration(cacheInterval));

            Secret actualFirst = await cachedSecretProvider.GetSecretAsync(keyName);
            testProviderStub.SecretValue = expectedSecondSecret;

            // Act
            await cachedSecretProvider.InvalidateSecretAsync(keyName);

            // Assert
            Secret actualSecond = await cachedSecretProvider.GetSecretAsync(keyName);
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst.Value);
            Assert.Equal(expectedSecondSecret, actualSecond.Value);
            Assert.Equal(2, testProviderStub.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task CacheSecretProvider_GetSecret_InvalidateSecret_ShouldRequestNewSecretEvenWithinCacheDuration()
        {
            // Arrange
            string expectedFirstSecret = Guid.NewGuid().ToString("N");
            string expectedSecondSecret = Guid.NewGuid().ToString("N");
            var testProviderStub = new TestSecretProviderStub(expectedFirstSecret);
            var cacheInterval = TimeSpan.FromSeconds(10);

            const string keyName = "MySecret";
            var cachedSecretProvider = new CachedSecretProvider(
                testProviderStub,
                new CacheConfiguration(cacheInterval));

            Secret actualFirst = cachedSecretProvider.GetSecret(keyName);
            testProviderStub.SecretValue = expectedSecondSecret;

            // Act
            await cachedSecretProvider.InvalidateSecretAsync(keyName);

            // Assert
            Secret actualSecond = cachedSecretProvider.GetSecret(keyName);
            Assert.True(actualFirst != null, "actualFirst != null");
            Assert.True(actualSecond != null, "actualSecond != null");

            Assert.Equal(expectedFirstSecret, actualFirst.Value);
            Assert.Equal(expectedSecondSecret, actualSecond.Value);
            Assert.Equal(2, testProviderStub.CallsMadeSinceCreation);
        }

        [Fact]
        public async Task GetSecrets_WithoutVersionedSecrets_ReturnsSingle()
        {
            // Arrange
            string secretName = BogusGenerator.Lorem.Word();
            string secretValue = BogusGenerator.Lorem.Word();
            var stub = new InMemorySecretProvider((secretName, secretValue));

            var cached = new CachedSecretProvider(stub, CacheConfiguration.Default);

            // Act
            IEnumerable<Secret> secrets = await cached.GetSecretsAsync(secretName, amountOfVersions: 3);

            // Assert
            Assert.Equal(secretValue, Assert.Single(secrets).Value);
        }

        [Fact]
        public async Task GetRawSecrets_WithoutVersionedSecrets_ReturnsSingle()
        {
            // Arrange
            string secretName = BogusGenerator.Lorem.Word();
            string secretValue = BogusGenerator.Lorem.Word();
            var stub = new InMemorySecretProvider((secretName, secretValue));

            var cached = new CachedSecretProvider(stub, CacheConfiguration.Default);

            // Act
            IEnumerable<string> secrets = await cached.GetRawSecretsAsync(secretName, amountOfVersions: 3);

            // Assert
            Assert.Equal(secretValue, Assert.Single(secrets));
        }

        [Fact]
        public async Task GetRawSecrets_AfterGetRawSecret_ReturnsCached()
        {
            // Arrange
            string secretName = BogusGenerator.Lorem.Word();
            string secretValue = BogusGenerator.Lorem.Word();
            int amountOfVersions = 1;
            var stub = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions);
            var cached = new CachedSecretProvider(stub, CacheConfiguration.Default);
            string secretValue1 = await cached.GetRawSecretAsync(secretName);
            Assert.Equal(secretValue, secretValue1);

            // Act
            IEnumerable<string> secretValues2 = await cached.GetRawSecretsAsync(secretName, amountOfVersions);

            // Assert
            Assert.Equal(secretValue, Assert.Single(secretValues2));
            Assert.Equal(1, stub.CallsSinceCreation);
        }

        [Fact]
        public async Task GetRawSecret_AfterGetRawSecrets_ReturnsCached()
        {
            // Arrange
            string secretName = BogusGenerator.Lorem.Word();
            string secretValue = BogusGenerator.Lorem.Word();
            int amountOfVersions = 1;
            var stub = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions);
            var cached = new CachedSecretProvider(stub, CacheConfiguration.Default);
            IEnumerable<string> secretValues1 = await cached.GetRawSecretsAsync(secretName, amountOfVersions);
            Assert.Equal(secretValue, Assert.Single(secretValues1));

            // Act
            string secretValue2 = await cached.GetRawSecretAsync(secretName);

            // Assert
            Assert.Equal(secretValue, secretValue2);
            Assert.Equal(1, stub.CallsSinceCreation);
        }

        [Fact]
        public async Task GetRawSecrets_AfterGetSecret_ReturnsCached()
        {
            // Arrange
            string secretName = BogusGenerator.Lorem.Word();
            string secretValue = BogusGenerator.Lorem.Word();
            int amountOfVersions = 1;
            var stub = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions);
            var cached = new CachedSecretProvider(stub, CacheConfiguration.Default);
            Secret secret1 = await cached.GetSecretAsync(secretName);
            Assert.Equal(secretValue, secret1.Value);

            // Act
            IEnumerable<string> secretValues2 = await cached.GetRawSecretsAsync(secretName, amountOfVersions);

            // Assert
            Assert.Equal(secretValue, Assert.Single(secretValues2));
            Assert.Equal(1, stub.CallsSinceCreation);
        }

        [Fact]
        public async Task GetSecret_AfterGetRawSecrets_ReturnsCached()
        {
            // Arrange
            string secretName = BogusGenerator.Lorem.Word();
            string secretValue = BogusGenerator.Lorem.Word();
            int amountOfVersions = 1;
            var stub = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions);
            var cached = new CachedSecretProvider(stub, CacheConfiguration.Default);
            IEnumerable<string> secretValues1 = await cached.GetRawSecretsAsync(secretName, amountOfVersions);
            Assert.Equal(secretValue, Assert.Single(secretValues1));

            // Act
            Secret secret2 = await cached.GetSecretAsync(secretName);

            // Assert
            Assert.Equal(secretValue, secret2.Value);
            Assert.Equal(1, stub.CallsSinceCreation);
        }

        [Fact]
        public async Task GetSecrets_WithHigherRequestedVersionsThanAvailable_IgnoresCache()
        {
            // Arrange
            string secretName = BogusGenerator.Lorem.Word();
            string secretValue = BogusGenerator.Lorem.Word();
            int amountOfVersions = 5;
            var stub = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions);
            var cached = new CachedSecretProvider(stub, CacheConfiguration.Default);

            IEnumerable<string> secretValues1 = await cached.GetRawSecretsAsync(secretName, amountOfVersions);
            Assert.Equal(amountOfVersions, secretValues1.Count());

            // Act
            IEnumerable<string> secretValues2 = await cached.GetRawSecretsAsync(secretName, 10);

            // Assert
            Assert.Equal(amountOfVersions, secretValues2.Count());
            Assert.Equal(2, stub.CallsSinceCreation);
        }

        [Fact]
        public async Task GetSecrets_WithLowerRequestedVersionsThanAvailable_UsesCache()
        {
            // Arrange
            string secretName = BogusGenerator.Lorem.Word();
            string secretValue = BogusGenerator.Lorem.Word();
            int amountOfVersions = 5;
            var stub = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions);
            var cached = new CachedSecretProvider(stub, CacheConfiguration.Default);

            IEnumerable<string> secretValues1 = await cached.GetRawSecretsAsync(secretName, amountOfVersions);
            Assert.Equal(amountOfVersions, secretValues1.Count());

            // Act
            IEnumerable<string> secretValues2 = await cached.GetRawSecretsAsync(secretName, 3);

            // Assert
            Assert.Equal(3, secretValues2.Count());
            Assert.Equal(1, stub.CallsSinceCreation);
        }
    }
}
