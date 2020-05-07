﻿using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class IHostBuilderExtensionsTests
    {
        [Fact]
        public async Task ConfigureSecretStore_AddInMemorySecretProvider_UsesInMemorySecretsInSecretStore()
        {
            // Arrange
            string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";
            var stubProvider = new InMemorySecretProvider((secretKey, secretValue));
            
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue, await provider.GetRawSecretAsync(secretKey));
        }

        [Fact]
        public async Task ConfigureSecretStore_AddMultipleSecretProviders_UsesAllSecretStores()
        {
            // Arrange
            string secretKey1 = "MySecret1";
            string secretValue1 = $"secret-{Guid.NewGuid()}";
            var stubProvider1 = new InMemorySecretProvider((secretKey1, secretValue1));
            
            string secretKey2 = "MySecret2";
            string secretValue2 = $"secret-{Guid.NewGuid()}";
            var stubProvider2 = new InMemorySecretProvider((secretKey2, secretValue2));

            string secretKey3 = "MySecret3";
            string secretValue3 = $"secret-{Guid.NewGuid()}";
            var stubProvider3 = new InMemorySecretProvider((secretKey3, secretValue3));

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((context, config, stores) =>
            {
                stores.AddProvider(stubProvider1);
                stores.AddProvider(stubProvider2);
            }).ConfigureSecretStore((config, stores) => stores.AddProvider(stubProvider3));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Equal(secretValue1, await provider.GetRawSecretAsync(secretKey1));
            Assert.Equal(secretValue2, await provider.GetRawSecretAsync(secretKey2));
            Assert.Equal(secretValue3, await provider.GetRawSecretAsync(secretKey3));
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariables_UsesEnvironmentVariableSecrets()
        {
            // Arrange
            string secretKey = "MySecret";
            string secretValue = $"secret-{Guid.NewGuid()}";

            var builder = new HostBuilder();

            using (TemporaryEnvironmentVariable.Create(secretKey, secretValue))
            {
                // Act
                builder.ConfigureSecretStore((config, stores) => stores.AddEnvironmentVariables());

                // Assert
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();
                Assert.Equal(secretValue, await provider.GetRawSecretAsync(secretKey));
            }
        }
    }
}
