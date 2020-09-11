using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class SecretStoreBuilderTests
    {
        [Fact]
        public void AddProvider_WithoutSecretProvider_Throws()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new SecretStoreBuilder(services);

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.AddProvider(secretProvider: null));
        }

        [Fact]
        public void AddProviderFunction_WithoutFunction_Throws()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new SecretStoreBuilder(services);

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.AddProvider(createSecretProvider: null));
        }
    }
}
