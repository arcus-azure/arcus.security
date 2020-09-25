using System;
using System.Security.Authentication;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Providers;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class MutateSecretNameSecretProviderTests
    {
        [Fact]
        public async Task GetRawSecret_WithDotsToCapitalsAndUnderscores_ReturnsSecret()
        {
            // Arrange
            var expected = Guid.NewGuid().ToString();
            var stubProvider = new InMemorySecretProvider(("ARCUS_KEYVAULT_SECRET", expected));

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider, name => name.ToUpper().Replace(".", "_"));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            string actual = await provider.GetRawSecretAsync("Arcus.KeyVault.Secret");
            Assert.Equal(expected, actual);
        }

        [Fact]
        public async Task GetSecret_OnlyMutationOnOneProvider_DoesntConflictWithOtherProviders()
        {
            // Arrange
            var expected = Guid.NewGuid().ToString();
            var stubProvider1 = new InMemorySecretProvider(("arcus.keyvault.first", Guid.NewGuid().ToString()));
            var stubProvider2 = new InMemorySecretProvider(("Arcus.KeyVault.Second", expected));

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider1, name => name.ToLower())
                      .AddProvider(stubProvider2);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Secret secret = await provider.GetSecretAsync("Arcus.KeyVault.Second");
            Assert.Equal(expected, secret.Value);
        }

        [Fact]
        public async Task GetRawSecret_WithMutation_FailsToRetrieveSecret()
        {
            // Arrange
            var stubProvider = new InMemorySecretProvider(("Arcus.KeyVault.Secret", Guid.NewGuid().ToString()));

            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(stubProvider, name => $"Prefix-{name}");
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetRawSecretAsync("Arcus.KeyVault.Secret"));
        }

        [Fact]
        public async Task GetSecret_WithCriticalException_ThrowsThroughMutatedSecretProvider()
        {
            // Arrange
            var saboteurProvider = new SaboteurSecretProvider(new AuthenticationException("Some authentication failure"));
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddProvider(saboteurProvider, name => "Extra.Ignored.Prefix-" + name)
                      .AddCriticalException<AuthenticationException>();
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<AuthenticationException>(() => provider.GetSecretAsync("some secret name"));
        }

        [Fact]
        public void CreateProvider_WithoutImplementation_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(
                () => new MutatedSecretNameSecretProvider(implementation: null, mutateSecretName: name => name, logger: NullLogger<MutatedSecretNameSecretProvider>.Instance));
        }

        [Fact]
        public void CreateProvider_WithoutMutationFunction_Throws()
        {
            Assert.ThrowsAny<ArgumentException>(
                () => new MutatedSecretNameSecretProvider(implementation: new InMemorySecretProvider(), mutateSecretName: null, logger: NullLogger<MutatedSecretNameSecretProvider>.Instance));
        }
    }
}
