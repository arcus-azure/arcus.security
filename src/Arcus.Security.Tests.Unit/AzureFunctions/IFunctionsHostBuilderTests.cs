using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Tests.Unit.AzureFunctions.Stubs;
using Arcus.Testing.Security.Providers.InMemory;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
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
            var stubProvider = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey] = $"secret-{Guid.NewGuid()}" });

            var builder = new StubFunctionsHostBuilder();

            // Act
            builder.ConfigureSecretStore(stores => stores.AddProvider(stubProvider));

            // Assert
            IServiceProvider serviceProvider = builder.Build();
            var secretProvider = serviceProvider.GetRequiredService<ICachedSecretProvider>();
            await Assert.ThrowsAsync<NotSupportedException>(() => secretProvider.InvalidateSecretAsync(secretKey));
        }

        [Fact]
        public async Task ConfigureSecretStore_AddInMemorySecretProvider_UsesInMemorySecretsInSecretStore()
        {
            // Arrange
            const string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey] = secretValue });

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
            var stubProvider1 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey1] = secretValue1 });

            string secretKey2 = "MySecret2";
            string secretValue2 = $"secret-{Guid.NewGuid()}";
            var stubProvider2 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey2] = secretValue2 });

            string secretKey3 = "MySecret3";
            string secretValue3 = $"secret-{Guid.NewGuid()}";
            var stubProvider3 = new InMemorySecretProvider(new Dictionary<string, string> { [secretKey3] = secretValue3 });

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
        
        [Fact]
        public async Task ConfigureSecretStore_WithDuplicateNames_MakesSubsetOfDuplicateSecretProviderNames()
        {
            // Arrange
            var name = $"duplicate-name-{Guid.NewGuid()}";
            string secretName1 = "MySecret-1", secretName2 = "My-Secret2", secretName3 = "My-Secret3", secretName4 = $"My-Secret4";
            string secretValue1 = $"secret-{Guid.NewGuid()}",
                   secretValue2 = $"secret-{Guid.NewGuid()}",
                   secretValue3 = $"secret-{Guid.NewGuid()}",
                   secretValue4 = $"secret-{Guid.NewGuid()}";
            var builder = new StubFunctionsHostBuilder();

            // Act
            builder.ConfigureSecretStore(stores =>
            {
                stores.AddProvider(new InMemorySecretProvider(new Dictionary<string, string> { [secretName1] = secretValue1 }), options => options.Name = name)
                      .AddProvider(new InMemorySecretProvider( new Dictionary<string, string> { [secretName3] = secretValue3 }), options => options.Name = "some other name")
                      .AddProvider(new InMemoryCachedSecretProvider(new Dictionary<string, string> { [secretName2] = secretValue2 }), options => options.Name = name)
                      .AddProvider(new InMemorySecretProvider(new Dictionary<string, string> { [secretName4] = secretValue4 }));
            });

            // Assert
            var store = builder.Build().GetRequiredService<ISecretStore>();
            ISecretProvider provider = store.GetProvider(name);
            Assert.IsNotType<InMemoryCachedSecretProvider>(provider);
            Assert.Equal(secretValue1, await provider.GetRawSecretAsync(secretName1));
            Assert.Equal(secretValue2, await provider.GetRawSecretAsync(secretName2));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretName3));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(secretName4));
        }

        [Fact]
        public void ConfigureSecretStore_WithDuplicateNames_FailsWhenRetrievingTypedSecretProvider()
        {
            // Arrange
            string name = $"duplicate-name-{Guid.NewGuid()}";
            var builder = new StubFunctionsHostBuilder();
            
            // Act
            builder.ConfigureSecretStore(stores =>
            {
                stores.AddProvider(new InMemorySecretProvider(), options => options.Name = name)
                      .AddProvider(new InMemorySecretProvider(), options => options.Name = name);
            });
            
            // Assert
            var store = builder.Build().GetRequiredService<ISecretStore>();
            Assert.Throws<InvalidOperationException>(() => store.GetProvider<InMemorySecretProvider>(name));
        }
        
        [Fact]
        public void ConfigureSecretStore_WithDuplicateNames_FailsWhenRetrievingTypedCachedSecretProvider()
        {
            // Arrange
            string name = $"duplicate-name-{Guid.NewGuid()}";
            var builder = new StubFunctionsHostBuilder();
            
            // Act
            builder.ConfigureSecretStore(stores =>
            {
                stores.AddProvider(new InMemoryCachedSecretProvider(), options => options.Name = name)
                      .AddProvider(new InMemoryCachedSecretProvider(), options => options.Name = name);
            });
            
            // Assert
            var store = builder.Build().GetRequiredService<ISecretStore>();
            Assert.Throws<InvalidOperationException>(() => store.GetProvider<InMemoryCachedSecretProvider>(name));
        }
    }
}
