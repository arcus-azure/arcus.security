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

            Assert.Equal(expectedValue, secretProvider.GetRawSecret(secretKey));
            Assert.Equal(expectedValue, secretProvider.GetSecret(secretKey).Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync(secretKey));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync(secretKey)).Value);
        }

        [Fact]
        public async Task DockerSecretsProvider_ReturnsNull_WhenSecretNotFound()
        {
            // Arrange
            var provider = new DockerSecretsSecretProvider(_secretLocation);
            
            // Act
            await SetSecretAsync("MyExistingSecret", "foo");

            // Assert
            var secretName = "MyNonExistingSecret";
            Assert.Null(provider.GetRawSecret(secretName));
            Assert.Null(provider.GetSecret(secretName).Value);
            Assert.Null(await provider.GetRawSecretAsync(secretName));
            Assert.Null((await provider.GetSecretAsync(secretName)).Value);
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

            var secretName = "ConnectionStrings:PersonDb";
            Assert.Equal(expectedValue, secretProvider.GetRawSecret(secretName));
            Assert.Equal(expectedValue, secretProvider.GetSecret(secretName).Value);
            Assert.Equal(expectedValue, await secretProvider.GetRawSecretAsync(secretName));
            Assert.Equal(expectedValue, (await secretProvider.GetSecretAsync(secretName)).Value);
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
