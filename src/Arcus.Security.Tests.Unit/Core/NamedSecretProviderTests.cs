using System;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class NamedSecretProviderTests
    {
        [Fact]
        public void GetCachedProvider_WithWrongCastType_Fails()
        {
            // Arrange
            var services = new ServiceCollection();
            var name = "TestProvider";

            // Act
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(
                    new InMemoryCachedSecretProvider(("Secret.Name", "Secret.Value")),
                    options => options.Name = name);
            });

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretStore>();
            Assert.ThrowsAny<InvalidCastException>(
                () => secretProvider.GetCachedProvider<KeyVaultCachedSecretProvider>(name));
        }
    }
}
