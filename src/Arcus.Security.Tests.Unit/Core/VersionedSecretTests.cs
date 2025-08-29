using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using Secret = Arcus.Security.Core.Secret;

namespace Arcus.Security.Tests.Unit.Core
{
    public class VersionedSecretTests
    {
        [Fact]
        public async Task GetRawSecret_WithoutComposite_Fallback()
        {
            // Arrange
            var services = new ServiceCollection();
            var secretName = "MySecret";
            var secretValue = "secretValue";
            var inMemory = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions: 3);
            var name = "InMemory";
            services.AddSecretStore(stores => stores.AddProvider(inMemory, options => options.Name = name));

            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretStore = serviceProvider.GetRequiredService<ISecretStore>();

            ISecretProvider secretProvider = secretStore.GetProvider(name);

            // Act
            IEnumerable<string> secrets = await secretProvider.GetRawSecretsAsync(secretName);

            // Assert
            Assert.Equal(secretValue, Assert.Single(secrets));
        }

        [Fact]
        public async Task GetSecret_WithoutComposite_Fallback()
        {
            // Arrange
            var services = new ServiceCollection();
            var secretName = "MySecret";
            var secretValue = "secretValue";
            var inMemory = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions: 3);
            var name = "InMemory";
            services.AddSecretStore(stores => stores.AddProvider(inMemory, options => options.Name = name));

            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretStore = serviceProvider.GetRequiredService<ISecretStore>();

            ISecretProvider secretProvider = secretStore.GetProvider(name);

            // Act
            IEnumerable<Secret> secrets = await secretProvider.GetSecretsAsync(secretName);

            // Assert
            Assert.Equal(secretValue, Assert.Single(secrets).Value);
        }
    }
}
