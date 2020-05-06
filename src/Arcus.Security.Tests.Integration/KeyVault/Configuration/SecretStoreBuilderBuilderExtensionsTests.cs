using System.Threading.Tasks;
using Arcus.Security.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault.Configuration
{
    [Trait(name: "Category", value: "Integration")]
    public class SecretStoreBuilderBuilderExtensionsTests : IntegrationTest
    {
        public SecretStoreBuilderBuilderExtensionsTests(ITestOutputHelper testOutput) : base(testOutput)
        {
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, applicationId, clientKey));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentity_GetSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, connectionString));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }
    }
}
