using System;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.UserSecrets
{
    public class SecretStoreBuilderExtensionsTests
    {
        [Fact]
        public void AddUserSecrets_WithoutAssembly_Fails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(assembly: null);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Fact]
        public void AddUserSecrets_WithNameAndMutationWithoutAssembly_Fails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(assembly: null, name: "Some name", mutateSecretName: secretName => secretName);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddUserSecrets_WithoutUserSecretsId_Fails(string userSecretsId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(userSecretsId);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddUserSecrets_WithNameAndMutationWithoutUserSecretsId_Fails(string userSecretsId)
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddUserSecrets(userSecretsId, name: "Some name", mutateSecretName: secretName => secretName);
            });

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
    }
}
