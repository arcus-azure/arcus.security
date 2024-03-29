﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Arcus.Testing.Security.Providers.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using Secret = Arcus.Security.Core.Secret;

namespace Arcus.Security.Tests.Unit.Core
{
    public class VersionedSecretTests
    {
        [Fact]
        public async Task GetRawSecret_WithVersion_ReturnsAll()
        {
            // Arrange
            var services = new ServiceCollection();
            var secretName = "MySecret";
            var amountOfVersions = 2;
            var secretValue = "secretValue";
            var inMemory = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions);
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(inMemory, options => options.AddVersionedSecret(secretName, amountOfVersions));
            });

            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            var versionedProvider = (IVersionedSecretProvider) secretProvider;

            AssertCollectionCount(await secretProvider.GetSecretsAsync(secretName), amountOfVersions, secret => Assert.Equal(secretValue, secret.Value));
            AssertCollectionCount(await secretProvider.GetRawSecretsAsync(secretName), amountOfVersions, value => Assert.Equal(secretValue, value));
            AssertCollectionCount(await versionedProvider.GetSecretsAsync(secretName, amountOfVersions), amountOfVersions, secret => Assert.Equal(secretValue, secret.Value));
            AssertCollectionCount(await versionedProvider.GetRawSecretsAsync(secretName, amountOfVersions), amountOfVersions, value => Assert.Equal(secretValue, value));
        }

        private static void AssertCollectionCount<T>(IEnumerable<T> sequence, int assertionLength, Action<T> assertion)
        {
            Assert.Collection(sequence, Enumerable.Repeat(assertion, assertionLength).ToArray());
        }

        [Fact]
        public async Task GetRawSecrets_WithCache_OnlyCalledOnce()
        {
            // Arrange
            var services = new ServiceCollection();
            var secretName = "MySecret";
            var amountOfVersions = 2;
            var inMemory = new InMemorySecretVersionProvider(secretName, "secretValue", amountOfVersions);
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(
                    new CachedSecretProvider(inMemory), 
                    options => options.AddVersionedSecret(secretName, amountOfVersions));
            });

            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            IEnumerable<string> secrets1 = await secretProvider.GetRawSecretsAsync(secretName);
            Assert.Equal(amountOfVersions, secrets1.Count());

            // Act
            IEnumerable<string> secrets2 = await secretProvider.GetRawSecretsAsync(secretName);
            
            // Assert
            Assert.Equal(amountOfVersions, secrets2.Count());
            Assert.Equal(1, inMemory.CallsSinceCreation);
        }

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

        [Fact]
        public async Task Invalidate_WithCachedVersionedSecrets_RemovesAll()
        {
            // Arrange
            var services = new ServiceCollection();
            var secretName = "MySecret";
            var secretValue = "secretValue";
            var amountOfVersions = 3;
            var inMemory = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions);
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(new CachedSecretProvider(inMemory), options => options.AddVersionedSecret(secretName, amountOfVersions));
            });

            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ICachedSecretProvider>();
            IEnumerable<Secret> secrets1 = await secretProvider.GetSecretsAsync(secretName);
            Assert.Equal(amountOfVersions, secrets1.Count());

            // Act
            await secretProvider.InvalidateSecretAsync(secretName);

            // Assert
            IEnumerable<Secret> secrets2 = await secretProvider.GetSecretsAsync(secretName);
            Assert.Equal(amountOfVersions, secrets2.Count());
            Assert.Equal(2, inMemory.CallsSinceCreation);
        }

        [Fact]
        public async Task Invalidate_WithCachedVersionedRawSecrets_RemovesAll()
        {
            // Arrange
            var services = new ServiceCollection();
            var secretName = "MySecret";
            var secretValue = "secretValue";
            var amountOfVersions = 3;
            var inMemory = new InMemorySecretVersionProvider(secretName, secretValue, amountOfVersions);
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(new CachedSecretProvider(inMemory), options => options.AddVersionedSecret(secretName, amountOfVersions));
            });

            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ICachedSecretProvider>();
            IEnumerable<Secret> secrets1 = await secretProvider.GetSecretsAsync(secretName);
            Assert.Equal(amountOfVersions, secrets1.Count());

            // Act
            await secretProvider.InvalidateSecretAsync(secretName);

            // Assert
            IEnumerable<string> secretValues2 = await secretProvider.GetRawSecretsAsync(secretName);
            Assert.Equal(amountOfVersions, secretValues2.Count());
            Assert.Equal(2, inMemory.CallsSinceCreation);
        }

        [Fact]
        public async Task GetRawSecretsAsync_WithNonVersionedSecretProviders_RunsThroughAllProviders()
        {
            // Arrange
            var services = new ServiceCollection();
            var secretName = "MySecret";
            var secretValue = Guid.NewGuid().ToString();

            var secretProvider1 = new InMemorySecretProvider();
            var secretProvider2 = new InMemorySecretProvider(new Dictionary<string, string> { [secretName] = secretValue });
            
            // Act
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(secretProvider1)
                      .AddProvider(secretProvider2);
            });

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            IEnumerable<string> rawSecrets = await secretProvider.GetRawSecretsAsync(secretName);
            Assert.Equal(new[] { secretValue }, rawSecrets);
        }

        [Fact]
        public async Task GetSecretsAsync_WithNonVersionedSecretProviders_RunsThroughAllProviders()
        {
            // Arrange
            var services = new ServiceCollection();
            var secretName = "MySecret";
            var secretValue = Guid.NewGuid().ToString();

            var secretProvider1 = new InMemorySecretProvider();
            var secretProvider2 = new InMemorySecretProvider(new Dictionary<string, string> { [secretName] = secretValue });
            
            // Act
            services.AddSecretStore(stores =>
            {
                stores.AddProvider(secretProvider1)
                      .AddProvider(secretProvider2);
            });

            // Assert
            IServiceProvider serviceProvider = services.BuildServiceProvider();
            var secretProvider = serviceProvider.GetRequiredService<ISecretProvider>();
            IEnumerable<Secret> secrets = await secretProvider.GetSecretsAsync(secretName);
            Assert.Equal(secretValue, Assert.Single(secrets.Select(secret => secret.Value)));
        }
    }
}
