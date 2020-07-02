using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Tests.Unit.AzureFunctions.Stubs;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.AzureFunctions
{
    public class IFunctionsHostBuilderTests
    {
        [Fact]
        public async Task ConfigureSecretStore_WithoutSecretProviders_ThrowsException()
        {
            // Arrange
            var builder = new StubFunctionsHostBuilder();

            // Act
            builder.ConfigureSecretStore(stores => { });

            // Assert
            IServiceProvider serviceProvider = builder.Build();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync("ignored-key"));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithoutFoundSecretProvider_ThrowsException()
        {
            // Arrange
            var builder = new StubFunctionsHostBuilder();
            var emptyProvider = new InMemorySecretProvider();

            // Act
            builder.ConfigureSecretStore(stores => stores.AddProvider(emptyProvider));

            // Assert
            IServiceProvider serviceProvider = builder.Build();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.GetSecretAsync("ignored-key"));
        }

        [Fact]
        public async Task ConfigureSecretStore_WithoutFoundCachedProvider_ThrowsException()
        {
            // Arrange
            const string secretKey = "MySecret";
            var stubProvider = new InMemorySecretProvider((secretKey, $"secret-{Guid.NewGuid()}"));

            var builder = new StubFunctionsHostBuilder();

            // Act
            builder.ConfigureSecretStore(stores => stores.AddProvider(stubProvider));

            // Assert
            IServiceProvider serviceProvider = builder.Build();
            var secretProvider = serviceProvider.GetRequiredService<ICachedSecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(() => secretProvider.InvalidateSecretAsync(secretKey));
        }

        [Fact]
        public async Task ConfigureSecretStore_AddInMemorySecretProvider_UsesInMemorySecretsInSecretStore()
        {
            // Arrange
            const string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider((secretKey, secretValue));

            var builder = new StubFunctionsHostBuilder();

            // Act
            builder.ConfigureSecretStore(stores => stores.AddProvider(stubProvider));

            // Assert
            IServiceProvider serviceProvider = builder.Build();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue, await secretProvider.GetRawSecretAsync(secretKey));
            Assert.NotNull(serviceProvider.GetService<ICachedSecretProvider>());
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

            var builder = new StubFunctionsHostBuilder();

            // Act
            builder.ConfigureSecretStore(stores =>
            {
                stores.AddProvider(stubProvider1);
                stores.AddProvider(stubProvider2);
            }).ConfigureSecretStore(stores => stores.AddProvider(stubProvider3));

            // Assert
            IServiceProvider serviceProvider = builder.Build();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue1, await secretProvider.GetRawSecretAsync(secretKey1));
            Assert.Equal(secretValue2, await secretProvider.GetRawSecretAsync(secretKey2));
            Assert.Equal(secretValue3, await secretProvider.GetRawSecretAsync(secretKey3));
        }
    }
}
