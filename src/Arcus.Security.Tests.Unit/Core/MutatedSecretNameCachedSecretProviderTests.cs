using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Providers;
using Arcus.Testing.Security.Providers.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class MutatedSecretNameCachedSecretProviderTests
    {
        [Fact]
        public async Task GetRawSecret_WithMutation_Succeeds()
        {
            // Arrange
            string expected = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemoryCachedSecretProvider(new Dictionary<string, string> { ["Arcus.KeyVault.Secret"] = expected });

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider, secretName => secretName.Replace(":", "."));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            string actual = await provider.GetRawSecretAsync("Arcus:KeyVault:Secret", ignoreCache: true);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public async Task GetSecret_WithMutation_Succeeds()
        {
            // Arrange
            string expected = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemoryCachedSecretProvider(new Dictionary<string, string> { ["Arcus.KeyVault.Secret"] = expected });

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider, secretName => secretName.Replace(":", "."));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            Secret secret = await provider.GetSecretAsync("Arcus:KeyVault:Secret", ignoreCache: true);
            Assert.Equal(expected, secret.Value);
        }

        [Fact]
        public async Task InvalidateSecret_WithMutation_Succeeds()
        {
            // Arrange
            string expected = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemoryCachedSecretProvider(new Dictionary<string, string> { ["Arcus.KeyVault.Secret"] = expected });

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider, secretName => secretName.Replace(":", "."));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
            await provider.InvalidateSecretAsync("Arcus:KeyVault:Secret");
        }

        [Fact]
        public void ConfigureSecretStore_WithDefault_FailsToRetrieveCacheConfiguration()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(new InMemorySecretProvider());
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ICachedSecretProvider>();
                Assert.Throws<NotSupportedException>(() => provider.Configuration);
            }
        }

        [Fact]
        public void CreateCachedProvider_WithoutImplementation_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(
                () => new MutatedSecretNameCachedSecretProvider(implementation: null, mutateSecretName: name => name, logger: NullLogger<MutatedSecretNameSecretProvider>.Instance));
        }

        [Fact]
        public void CreateCachedProvider_WithoutMutationFunction_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(
                () => new MutatedSecretNameCachedSecretProvider(implementation: Mock.Of<ICachedSecretProvider>(), mutateSecretName: null, logger: NullLogger<MutatedSecretNameSecretProvider>.Instance));
        }
    }
}
