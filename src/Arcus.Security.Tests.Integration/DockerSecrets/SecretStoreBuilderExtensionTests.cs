using Arcus.Security.Core;
using Arcus.Security.Providers.DockerSecrets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.DockerSecrets
{
    public class SecretStoreBuilderExtensionTests : IntegrationTest, IDisposable
    {
        private readonly string _secretLocation = Path.Combine(Path.GetTempPath(), "dockersecretstests");

        public SecretStoreBuilderExtensionTests(ITestOutputHelper testOutput) : base(testOutput)
        {
            Directory.CreateDirectory(_secretLocation);
        }

        [Fact]
        public async Task AddKeyPerFileSecrets_WithPath_ResolvesSecret()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            var secretKey = "MySuperSecret";
            await SetSecretAsync(secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddDockerSecrets(_secretLocation));

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            string actualValue = await secretProvider.GetRawSecretAsync(secretKey);
            Assert.Equal(expectedValue, actualValue);
        }

        [Fact]
        public async Task KeyPerFileSecrets_HierarchicalKeys_AreSupported()
        {
            // Arrange
            var expectedValue = Guid.NewGuid().ToString();
            var secretKey = "ConnectionStrings__PersonDb";
            await SetSecretAsync(secretKey, expectedValue);

            var hostBuilder = new HostBuilder();

            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddDockerSecrets(_secretLocation));

            // Assert
            IHost host = hostBuilder.Build();
            var secretProvider = host.Services.GetRequiredService<ISecretProvider>();

            string actualValue = await secretProvider.GetRawSecretAsync("ConnectionStrings:PersonDb");
            Assert.Equal(expectedValue, actualValue);
        }

        private async Task SetSecretAsync(string secretKey, string secretValue)
        {
            await File.WriteAllTextAsync(Path.Combine(_secretLocation, secretKey), secretValue);
        }

        /// <summary>Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.</summary>
        public void Dispose()
        {
            Directory.Delete(_secretLocation, true);
        }
    }
}
