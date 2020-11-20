using System;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.DockerSecrets
{
    public class SecretStoreBuilderExtensionsTests
    {
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddDockerSecrets_WithoutDirectoryPath_Throws(string directoryPath)
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddDockerSecrets(directoryPath);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddDockerSecrets_WithoutDirectoryPathWithOptions_Throws(string directoryPath)
        {
            // Arrange
            var builder = new HostBuilder();
            
            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddDockerSecrets(directoryPath, options => options.Name = "Some name");
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
    }
}
