using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Tests.Integration.KeyVault.Fixture;
using Azure.Identity;
using Bogus;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    public partial class KeyVaultSecretProviderTests
    {
        private static readonly Faker Bogus = new();

        private string SecretName { get; } = $"name{Bogus.Random.Guid():N}";
        private string CurrentSecretValue { get; } = $"current-{Bogus.Random.Guid()}";
        private string NewSecretValue { get; } = $"new-{Bogus.Random.Guid()}";

        [Fact]
        public async Task StoreSecret_WithCachedSecret_InvalidatesSecretInStore()
        {
            // Arrange
            using var _ = UseTemporaryManagedIdentityConnection();
            using IHost host = CreateApplicationWithStore(store =>
            {
                store.AddAzureKeyVault(VaultUri, new DefaultAzureCredential())
                     .UseCaching(TimeSpan.FromHours(1));
            });
            var store = host.Services.GetRequiredService<ISecretStore>();

            await using var secret = await TemporaryKeyVaultSecret.CreateIfNotExistsAsync(SecretName, CurrentSecretValue, Configuration, Logger);
            Assert.Equal(CurrentSecretValue, await store.GetSecretAsync(SecretName));

            var provider = store.GetProvider<KeyVaultSecretProvider>();

            // Act
            await provider.SetSecretAsync(SecretName, NewSecretValue);

            // Assert
            Assert.Equal(NewSecretValue, await store.GetSecretAsync(SecretName));
        }

        private IHost CreateApplicationWithStore(Action<SecretStoreBuilder> configureSecretStore)
        {
            return Host.CreateDefaultBuilder()
                       .ConfigureLogging(logging =>
                       {
                           logging.SetMinimumLevel(LogLevel.Trace)
                                  .AddXunitTestLogging(TestOutput);
                       })
                       .ConfigureSecretStore((_, store) => configureSecretStore(store))
                       .Build();
        }
    }
}
