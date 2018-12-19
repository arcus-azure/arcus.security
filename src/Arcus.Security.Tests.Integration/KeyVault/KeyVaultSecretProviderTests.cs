using System;
using System.IO;
using System.Threading.Tasks;
using Arcus.Security.Core.Exceptions;
using Arcus.Security.KeyVault;
using Arcus.Security.KeyVault.Factories;
using Arcus.Security.Tests.Integration.Logging;
using Microsoft.Extensions.Configuration;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    [Trait(name: "Category", value: "Integration")]
    public class KeyVaultSecretProviderTests
    {
        // The same tests should be tested with different KeyVaultClientFactories 
        // What's the best approach for this ?

        private readonly XunitTestLogger _testLogger;

        public KeyVaultSecretProviderTests(ITestOutputHelper testOutput)
        {
            _testLogger = new XunitTestLogger(testOutput);

            // The appsettings.local.json allows users to override (gitignored) settings locally for testing purposes
            Configuration = new ConfigurationBuilder()
                .AddEnvironmentVariables()
                .AddJsonFile(path: "appsettings.json")
                .AddJsonFile(path: "appsettings.local.json", optional: true)
                .Build();
        }


        protected IConfiguration Configuration { get; }

        
        [Fact]
        public async Task KeyVaultSecretProvider_Get_Succeeds()
        {
            // Arrange
            var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            // Act
            KeyVaultSecretProvider keyVaultSecretProvider = new KeyVaultSecretProvider(
                new ServicePrincipalKeyVaultClientFactory(clientId, clientKey), keyVaultUri
                );
            string secretValue = await keyVaultSecretProvider.Get(keyName);

            // Assert
            Assert.NotNull(secretValue);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_GetNonExistingKey_ThrowsKeyNotFoundException()
        {
            // Arrange
            var clientId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ClientId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Guid.NewGuid().ToString("N");

            // Act
            KeyVaultSecretProvider keyVaultSecretProvider = new KeyVaultSecretProvider(
                new ServicePrincipalKeyVaultClientFactory(clientId, clientKey), keyVaultUri
            );

            // Assert
            await Assert.ThrowsAnyAsync<SecretNotFoundException>(async () =>
            {
                await keyVaultSecretProvider.Get(keyName);
            });
        }
    }
}
