using Arcus.Security.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.IO;
using System.Threading.Tasks;
using Arcus.Security.Providers.DockerSecrets;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.DockerSecrets
{
    public class SecretStoreBuilderExtensionTests : IntegrationTest
    {
        private readonly string _secretLocation = Path.Combine(Path.GetTempPath(), "dockersecretstests");

        public SecretStoreBuilderExtensionTests(ITestOutputHelper testOutput) : base(testOutput)
        {
            Directory.CreateDirectory(_secretLocation);
        }

        [Fact]
        public async Task AddDockerSecrets_WithPath_ResolvesSecret()
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
        public async Task DockerSecretsProvider_ReturnsNull_WhenSecretNotFound()
        {
            var provider = new DockerSecretsSecretProvider(_secretLocation);
            await SetSecretAsync("MyExistingSecret", "foo");

            var secret = await provider.GetRawSecretAsync("MyNonExistingSecret");

            Assert.Null(secret);
        }

        [Fact]
        public async Task DockerSecrets_HierarchicalKeys_AreSupported()
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

        [Fact]
        public void DockerSecrets_WithRelativeDirectoryPath_Fails()
        {
            // Arrange
            var hostBuilder = new HostBuilder();
            
            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddDockerSecrets("./foo"));
            
            // Assert
            Assert.ThrowsAny<ArgumentException>(() => hostBuilder.Build());
        }

        [Fact]
        public void DockerSecrets_WithNonExistingDirectory_Fails()
        {
            // Arrange
            var hostBuilder = new HostBuilder();
            
            // Act
            hostBuilder.ConfigureSecretStore((config, stores) => stores.AddDockerSecrets("/foo/bar"));
            
            // Assert
            Assert.Throws<DirectoryNotFoundException>(() => hostBuilder.Build());
        }

        private async Task SetSecretAsync(string secretKey, string secretValue)
        {
            await File.WriteAllTextAsync(Path.Combine(_secretLocation, secretKey), secretValue);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            Directory.Delete(_secretLocation, true);
        }
    }
}
