using System;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
        public async Task ConfigureSecretStore_WithSpecificCriticalException_ThrowsCriticalExceptionWhenThrownInSecretProvider()
        {
            // Arrange
            var stubProvider = new SaboteurSecretProvider(new AuthenticationException("Some authentication failure"));
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddCriticalException<AuthenticationException>()
                      .AddProvider(stubProvider);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<AuthenticationException>(() => provider.GetRawSecretAsync("some secret name"));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithMultipleSpecificCriticalExceptions_ThrowsAggregateExceptionWithAllThrownCriticalExceptionsWhenThrownInSecretProvider()
        {
            // Arrange
            var stubProvider1 = new SaboteurSecretProvider(new CryptographicException("Some cryptographic failure"));
            var stubProvider2 = new SaboteurSecretProvider(new AuthenticationException("Some authentication failure"));

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddCriticalException<CryptographicException>()
                      .AddCriticalException<AuthenticationException>()
                      .AddProvider(stubProvider1)
                      .AddProvider(stubProvider2);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var exception = await Assert.ThrowsAsync<AggregateException>(() => provider.GetSecretAsync("some secret name"));
            Assert.Collection(exception.InnerExceptions, 
                ex => Assert.IsType<CryptographicException>(ex),
                ex => Assert.IsType<AuthenticationException>(ex));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithSpecificCriticalExceptionFilter_ThrowsSpecificCriticalExceptionThatMatchesFilter()
        {
            // Arrange
            const string expectedMessage = "This is a specific message";
            var stubProvider1 = new SaboteurSecretProvider(new AuthenticationException(expectedMessage));
            var stubProvider2 = new SaboteurSecretProvider(new AuthenticationException("This is a different message"));

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddCriticalException<AuthenticationException>(ex => ex.Message == expectedMessage)
                      .AddProvider(stubProvider1)
                      .AddProvider(stubProvider2);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var exception = await Assert.ThrowsAsync<AuthenticationException>(() => provider.GetRawSecretAsync("some secret name"));
            Assert.Equal(expectedMessage, exception.Message);
        }

        [Fact]
        public async Task ConfigureSecretStore_WithInvalidExceptionFilter_CatchesGeneral()
        {
            // Arrange
            var stubProvider = new InMemorySecretProvider();
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddCriticalException<CryptographicException>(
                    ex => throw new Exception("Throw something to let the exception filter fail"));

                stores.AddProvider(stubProvider);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync("some secret name"));
        }

        [Fact]
        public void ConfigureSecretStore_WithoutExceptionFilter_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddCriticalException<AuthenticationException>(exceptionFilter: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
    }
}
