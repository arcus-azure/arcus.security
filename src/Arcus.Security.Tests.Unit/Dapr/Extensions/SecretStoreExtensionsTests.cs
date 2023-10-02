using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.Dapr.Extensions
{
    public class SecretStoreExtensionsTests
    {
        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddDaprSecretStore_WithoutSecretStore_Fails(string secretStore)
        {
            // Arrange
            var services = new ServiceCollection();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => services.AddSecretStore(stores => stores.AddDaprSecretStore(secretStore)));
        }

        [Theory]
        [ClassData(typeof(Blanks))]
        public void AddDaprSecretStoreWithConfig_WithoutSecretStore_Fails(string secretStore)
        {
            // Arrange
            var services = new ServiceCollection();

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => services.AddSecretStore(stores => stores.AddDaprSecretStore(secretStore, opt => { })));
        }
    }
}
