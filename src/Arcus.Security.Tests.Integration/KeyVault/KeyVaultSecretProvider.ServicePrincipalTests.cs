using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Azure;
using Azure.Identity;
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
        public async Task KeyVaultSecretProvider_WithServicePrincipalWithTenant_GetSecret_Succeeds()
        {
            // Arrange
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                tokenCredential: new ClientSecretCredential(TenantId, ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Act / Assert
            AssertSecret(keyVaultSecretProvider.GetSecret(TestSecretName));
            AssertSecretValue(keyVaultSecretProvider.GetRawSecret(TestSecretName));
            AssertSecret(await keyVaultSecretProvider.GetSecretAsync(TestSecretName));
            AssertSecretValue(await keyVaultSecretProvider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task KeyVaultSecretProvider_WithServicePrincipalWithTenant_GetSecret_NonExistingSecret_ThrowsSecretNotFoundException()
        {
            // Arrange
            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";

            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                tokenCredential: new ClientSecretCredential(TenantId, ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Assert
            await Assert.ThrowsAnyAsync<SecretNotFoundException>(async () =>
            {
                // Act
                await keyVaultSecretProvider.GetSecretAsync(notExistingSecretName);
            });
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipal_GetSecretFails()
        {
            // Arrange
            var keyName = "UnknownSecretName";
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, ClientId, ClientSecret, cacheConfiguration: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(keyName));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(keyName));
        }

        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 2)]
        public async Task AddAzureKeyVaultWithDependencyTracking_WithServicePrincipal_GetSecretFails(bool trackDependency, int expectedTrackedDependencies)
        {
            // Arrange
            var keyName = "UnknownSecretName";

            var builder = new HostBuilder();
            builder.UseSerilog(Logger, dispose: true);

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, ClientId, ClientSecret, cacheConfiguration: null,
                    configureOptions: options => options.TrackDependency = trackDependency, 
                    configureProviderOptions: null);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(keyName));
            }
            
            Assert.NotEmpty(InMemoryLogSink.CurrentLogEmits);
            AssertTrackedAzureKeyVaultDependency(expectedTrackedDependencies);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipalToDots_GetsSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    VaultUri, TenantId, ClientId, ClientSecret, cacheConfiguration: null,
                    mutateSecretName: secretName => secretName.Remove(0, 5),
                    configureOptions: null, name: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            string appendedKeyName = "Test-" + TestSecretName;
            AssertSecret(await provider.GetSecretAsync(appendedKeyName));
            AssertSecretValue(await provider.GetRawSecretAsync(appendedKeyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipalWrongMutation_GetsSecretsFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    VaultUri, TenantId, ClientId, ClientSecret, cacheConfiguration: null,
                    mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName, 
                    name: null, configureOptions: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(TestSecretName));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(TestSecretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(TestSecretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, ClientId, ClientSecret, CacheConfiguration.Default);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            AssertSecret(await provider.GetSecretAsync(TestSecretName));
            AssertSecretValue(await provider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipal_GetSecretFails()
        {
            // Arrange
            var keyName = "UnknownSecretName";
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, ClientId, ClientSecret, CacheConfiguration.Default);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(keyName));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipalRemovesPrefix_GetsSecretsSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    VaultUri, TenantId, ClientId, ClientSecret, CacheConfiguration.Default, 
                    mutateSecretName: secretName => secretName.Remove(0, 5), 
                    name: null, configureOptions: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            string appendedKeyName = "Test-" + TestSecretName;
            AssertSecret(await provider.GetSecretAsync(appendedKeyName));
            AssertSecretValue(await provider.GetRawSecretAsync(appendedKeyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipalWrongMutation_GetsSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    VaultUri, TenantId, ClientId, ClientSecret, CacheConfiguration.Default, 
                    mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName,
                    configureOptions: null, name: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();
            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(TestSecretName));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(TestSecretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(TestSecretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(TestSecretName));
        }

         [Fact]
        public async Task AddAzureKeyVault_WithWrongServicePrincipalCredentials_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, "wrong-app-id", "wrong-access-key", cacheConfiguration: null);
            });

            // Assert
           using  IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<AuthenticationFailedException>(() => provider.GetSecretAsync(TestSecretName));
            await Assert.ThrowsAsync<AuthenticationFailedException>(() => provider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithWrongUnauthorizedServicePrincipal_Throws()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:UnauthorizedServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:UnauthorizedServicePrincipal:AccessKey");
            string keyName = TestSecretName;

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, applicationId, clientKey, cacheConfiguration: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var exceptionFromSecretAsync = await Assert.ThrowsAsync<RequestFailedException>(() => provider.GetSecretAsync(keyName));
            var exceptionFromRawSecretAsync = await Assert.ThrowsAsync<RequestFailedException>(() => provider.GetRawSecretAsync(keyName));
            Assert.Equal((int) HttpStatusCode.Forbidden, exceptionFromSecretAsync.Status);
            Assert.Equal((int) HttpStatusCode.Forbidden, exceptionFromRawSecretAsync.Status);
        }

        [Fact]
        public async Task NewKeyVaultSecretProvider_ReturnsManySecrets_Succeeds()
        {
            // Arrange
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                tokenCredential: new ClientSecretCredential(TenantId, ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Act
            IEnumerable<Secret> secrets = await keyVaultSecretProvider.GetSecretsAsync(TestSecretName, amountOfVersions: 2);

            // Assert
            Assert.True(10 >= secrets.Count(), "should only retrieve 10 or less versioned secrets");
            Assert.Equal(TestSecretVersion, secrets.ElementAt(0).Version);
        }

        [Fact]
        public async Task NewKeyVaultSecretProvider_ReturnsOnlyAvailableSecrets_Succeeds()
        {
            // Arrange
            var keyVaultSecretProvider = new KeyVaultSecretProvider(
                tokenCredential: new ClientSecretCredential(TenantId, ClientId, ClientSecret), 
                vaultConfiguration: new KeyVaultConfiguration(VaultUri));

            // Act
            IEnumerable<Secret> secrets = await keyVaultSecretProvider.GetSecretsAsync(TestSecretName, amountOfVersions: 10);

            // Assert
            Assert.True(10 >= secrets.Count(), "should only retrieve 10 or less versioned secrets");
            Assert.Equal(TestSecretVersion, secrets.ElementAt(0).Version);
        }
    }
}
