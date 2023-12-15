using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Integration.Fixture;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Xunit;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    [Trait(name: "Category", value: "Integration")]
    public partial class KeyVaultSecretProviderTests
    {
        [Fact]
        public async Task KeyVaultSecretProvider_WithUserAssignedManagedIdentity_GetSecret_Succeeds()
        {
            // Arrange
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                var keyVaultSecretProvider = new KeyVaultSecretProvider(
                        tokenCredential: new ChainedTokenCredential(new ManagedIdentityCredential(ClientId), new EnvironmentCredential()),
                        vaultConfiguration: new KeyVaultConfiguration(VaultUri));

                // Act / Assert
                AssertSecret(keyVaultSecretProvider.GetSecret(TestSecretName));
                AssertSecretValue(keyVaultSecretProvider.GetRawSecret(TestSecretName));
                AssertSecret(await keyVaultSecretProvider.GetSecretAsync(TestSecretName));
                AssertSecretValue(await keyVaultSecretProvider.GetRawSecretAsync(TestSecretName));
            }
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithUserAssignedManagedIdentity_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                var notExistingSecretName = $"secret-{Guid.NewGuid():N}";
                var keyVaultSecretProvider = new KeyVaultSecretProvider(
                    tokenCredential: new ChainedTokenCredential(new ManagedIdentityCredential(ClientId), new EnvironmentCredential()),
                    vaultConfiguration: new KeyVaultConfiguration(VaultUri));

                // Assert
                await Assert.ThrowsAsync<SecretNotFoundException>(async () =>
                {
                // Act
                await keyVaultSecretProvider.GetSecretAsync(notExistingSecretName);
                }); 
            }
        }

        [Fact]
        public async Task KeyVaultSecretProvider_StoreSecret_Succeeds()
        {
            // Arrange
            var secretName = $"Test-Secret-{Guid.NewGuid()}";
            var secretValue = Guid.NewGuid().ToString();

            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                var tokenCredential = new ChainedTokenCredential(new ManagedIdentityCredential(ClientId), new EnvironmentCredential());
                try
                {
                    var keyVaultSecretProvider = new KeyVaultSecretProvider(
                        tokenCredential: tokenCredential,
                        vaultConfiguration: new KeyVaultConfiguration(VaultUri));

                    // Act
                    Secret secret = await keyVaultSecretProvider.StoreSecretAsync(secretName, secretValue);

                    // Assert
                    Assert.Equal(secretValue, secretValue);
                    Secret fetchedSecret = await keyVaultSecretProvider.GetSecretAsync(secretName);
                    Assert.Equal(secretValue, fetchedSecret.Value);
                    Assert.Equal(secret.Version, fetchedSecret.Version);
                    Assert.Equal(secret.Expires, fetchedSecret.Expires);
                }
                finally
                {
                    var client = new SecretClient(new Uri(VaultUri), tokenCredential);
                    await client.StartDeleteSecretAsync(secretName);
                }
            }
        }

         [Fact]
        public async Task AddAzureKeyVault_WithManagedIdentity_GetSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(VaultUri, cacheConfiguration: null, ClientId));

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                using IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                AssertSecret(provider.GetSecret(TestSecretName));
                AssertSecretValue(provider.GetRawSecret(TestSecretName));
                AssertSecret(await provider.GetSecretAsync(TestSecretName));
                AssertSecretValue(await provider.GetRawSecretAsync(TestSecretName));
            }
        }

        [Fact]
        public async Task AddAzureKeyVaultSimple_WithManagedIdentity_GetSecretSucceeds()
        {
            // Arrange
            string prefix = "Test-";
            
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri,
                    cacheConfiguration: null,
                    clientId: ClientId,
                    configureOptions: options => { },
                    name: "Azure Key Vault",
                    mutateSecretName: secretName => secretName.Remove(0, prefix.Length));
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                using IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                string appendedKeyName = "Test-" + TestSecretName;
                AssertSecret(provider.GetSecret(appendedKeyName));
                AssertSecretValue(provider.GetRawSecret(appendedKeyName));
                AssertSecret(await provider.GetSecretAsync(appendedKeyName));
                AssertSecretValue(await provider.GetRawSecretAsync(appendedKeyName));
            }
        }

        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 2)]
        public async Task AddAzureKeyVaultWithDependencyTracking_WithManagedIdentity_GetSecretSucceeds(bool trackDependency, int expectedTrackedDependencies)
        {
            // Arrange
            var builder = new HostBuilder();
            builder.UseSerilog(Logger, dispose: true);

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri, cacheConfiguration: null, clientId: ClientId, 
                    configureOptions: options => options.TrackDependency = trackDependency, 
                    name: null, mutateSecretName: null);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                AssertSecret(await provider.GetSecretAsync(TestSecretName));
                AssertSecretValue(await provider.GetRawSecretAsync(TestSecretName));
            }

            AssertTrackedAzureKeyVaultDependency(expectedTrackedDependencies);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri, clientId: ClientId, 
                    mutateSecretName: secretName => secretName.Remove(0, 5),
                    configureOptions: null, cacheConfiguration: null,
                    name: null);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                using IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                string appendedKeyName = "Test-" + TestSecretName;
                AssertSecret(provider.GetSecret(appendedKeyName));
                AssertSecretValue(provider.GetRawSecret(appendedKeyName));
                AssertSecret(await provider.GetSecretAsync(appendedKeyName));
                AssertSecretValue(await provider.GetRawSecretAsync(appendedKeyName));
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri, clientId: ClientId, cacheConfiguration: null, 
                    mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName,
                    configureOptions: null,
                    name: null);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                using IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(TestSecretName));
                Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(TestSecretName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(TestSecretName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(TestSecretName));
            }
        }

        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 2)]
        public async Task AddAzureKeyVaultWithDependencyTracking_WithManagedIdentityWrongMutation_GetsSecretFails(bool trackDependency, int expectedTrackedDependencies)
        {
            // Arrange
            var builder = new HostBuilder();
            builder.UseSerilog(Logger, dispose: true);

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri, clientId: ClientId, cacheConfiguration: null,
                    configureOptions: options => options.TrackDependency = trackDependency,
                    mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName,
                    name: null);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                using (IHost host = builder.Build())
                {
                    var provider = host.Services.GetRequiredService<ISecretProvider>();
                    await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(TestSecretName));
                    await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(TestSecretName));
                }
            }

            AssertTrackedAzureKeyVaultDependency(expectedTrackedDependencies);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedIdentity_GetSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(VaultUri, cacheConfiguration, ClientId, configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                using IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                AssertSecret(provider.GetSecret(TestSecretName));
                AssertSecretValue(provider.GetRawSecret(TestSecretName));
                AssertSecret(await provider.GetSecretAsync(TestSecretName));
                AssertSecretValue(await provider.GetRawSecretAsync(TestSecretName));
                Assert.True(cacheConfiguration.IsCalled); 
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedIdentity_GetSecretFails()
        {
            // Arrange
            var keyName = "UnknownSecretName";

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(VaultUri, clientId: ClientId, cacheConfiguration: cacheConfiguration, configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                using IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(keyName));
                Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(keyName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(keyName));
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri, clientId: ClientId, cacheConfiguration: cacheConfiguration, 
                    mutateSecretName: secretName => secretName.Remove(0, 5),
                    configureOptions: null,
                    name: null);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                using IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                string appendedKeyName = "Test-" + TestSecretName;
                AssertSecret(provider.GetSecret(appendedKeyName));
                AssertSecretValue(provider.GetRawSecret(appendedKeyName));
                AssertSecret(await provider.GetSecretAsync(appendedKeyName));
                AssertSecretValue(await provider.GetRawSecretAsync(appendedKeyName));
                Assert.True(cacheConfiguration.IsCalled); 
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri, clientId: ClientId, cacheConfiguration: cacheConfiguration, 
                    mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName,
                    configureOptions: null,
                    name: null);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                using IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(TestSecretName));
                Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(TestSecretName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(TestSecretName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(TestSecretName));
            }
        }

        [Fact]
        public async Task CachedKeyVaultSecretProvider_StoreSecret_Succeeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            string clientId = Configuration.GetServicePrincipalClientId();
            string clientKey = Configuration.GetServicePrincipalClientSecret();
            
            var secretName = $"Test-Secret-{Guid.NewGuid()}";
            var secretValue = Guid.NewGuid().ToString();
            
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientKey))
            {
                var tokenCredential = new ChainedTokenCredential(new ManagedIdentityCredential(clientId), new EnvironmentCredential());
                var keyVaultSecretProvider = new KeyVaultSecretProvider(
                    tokenCredential: tokenCredential,
                    vaultConfiguration: new KeyVaultConfiguration(keyVaultUri));
                var cachedSecretProvider = new KeyVaultCachedSecretProvider(keyVaultSecretProvider);

                try
                {
                    // Act
                    Secret secret = await cachedSecretProvider.StoreSecretAsync(secretName, secretValue);

                    // Assert
                    Assert.NotNull(secret);
                    Assert.NotNull(secret.Value);
                    Assert.NotNull(secret.Version);
                    AssertEqualSecret(secret, cachedSecretProvider.GetSecret(secretName));
                    AssertEqualSecret(secret, cachedSecretProvider.GetRawSecret(secretName));
                    AssertEqualSecret(secret, await cachedSecretProvider.GetSecretAsync(secretName));
                    AssertEqualSecret(secret, await cachedSecretProvider.GetRawSecretAsync(secretName));
                }
                finally
                {
                     var client = new SecretClient(new Uri(keyVaultUri), tokenCredential);
                    await client.StartDeleteSecretAsync(secretName);
                }
            }
        }

        private static void AssertEqualSecret(Secret expected, string secretValue)
        {
            Assert.Equal(expected.Value, secretValue);
        }

        private static void AssertEqualSecret(Secret expected, Secret actual)
        {
            Assert.Equal(expected.Value, actual.Value);
            Assert.Equal(expected.Version, actual.Version);
            Assert.Equal(expected.Expires, actual.Expires);
        }
    }
}
