using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Security.Tests.Integration.KeyVault.Configuration;
using Azure;
using Azure.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Serilog;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    [Trait(name: "Category", value: "Integration")]
    public class SecretStoreBuilderExtensionsTests : IntegrationTest
    {
        public SecretStoreBuilderExtensionsTests(ITestOutputHelper testOutput) : base(testOutput)
        {
        }

        private KeyVaultConfig KeyVault => Configuration.GetKeyVaultConfig();
        private string TenantId => KeyVault.Azure.TenantId;
        private string ClientId => KeyVault.ServicePrincipal.ClientId;
        private string ClientSecret => KeyVault.ServicePrincipal.ClientSecret;
        private string TestSecretName => KeyVault.SecretName;
        private string VaultUri => KeyVault.VaultUri;
        private string MsiConnectionString => Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();
            builder.UseSerilog(SerilogLogger, dispose: true);

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, ClientId, ClientSecret);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
                AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
            }
        }

        private void AssertNotNullSecret(Secret secret)
        {
            Assert.NotNull(secret);
            AssertNotNullSecret(secret.Value);
            Assert.NotNull(secret.Version);
        }

        private void AssertNotNullSecret(string secretValue)
        {
            Assert.NotNull(secretValue);
        }

        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 2)]
        public async Task AddAzureKeyVaultWithDependencyTracking_WithServicePrincipal_GetSecretSucceeds(bool trackDependency, int expectedTrackedDependencies)
        {
            // Arrange
            var builder = new HostBuilder();
            builder.UseSerilog(SerilogLogger, dispose: true);

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipalWithOptions(VaultUri, ClientId, ClientSecret, 
                    configureOptions: options => options.TrackDependency = trackDependency);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
                AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
            }
            
            AssertTrackedAzureKeyVaultDependency(expectedTrackedDependencies);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipal_GetSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, ClientId, ClientSecret);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var keyName = "UnknownSecretName";
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
            var builder = new HostBuilder();
            builder.UseSerilog(SerilogLogger, dispose: true);

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipalWithOptions(VaultUri, ClientId, ClientSecret, 
                    configureOptions: options => options.TrackDependency = trackDependency);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                var keyName = "UnknownSecretName";
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
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipalWithOptions(
                    VaultUri, ClientId, ClientSecret, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            string appendedKeyName = "Test-" + TestSecretName;
            AssertNotNullSecret(await provider.GetSecretAsync(appendedKeyName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(appendedKeyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipalWrongMutation_GetsSecretsFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipalWithOptions(
                    VaultUri, ClientId, ClientSecret, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName, allowCaching: false);
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
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, ClientId, ClientSecret, allowCaching: true);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipal_GetSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, ClientId, ClientSecret, allowCaching: true);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var keyName = "UnknownSecretName";
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
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipalWithOptions(
                    VaultUri, ClientId, ClientSecret, allowCaching: true, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            string appendedKeyName = "Test-" + TestSecretName;
            AssertNotNullSecret(await provider.GetSecretAsync(appendedKeyName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(appendedKeyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipalWrongMutation_GetsSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipalWithOptions(
                    VaultUri, ClientId, ClientSecret, allowCaching: true, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
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
        public async Task AddAzureKeyVault_WithManagedServiceIdentity_GetSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithManagedServiceIdentity(VaultUri, MsiConnectionString));

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
        }

        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 2)]
        public async Task AddAzureKeyVaultWithOptions_WithManagedServiceIdentity_GetSecretSucceeds(bool trackDependency, int expectedTrackedDependencies)
        {
            // Arrange
            var builder = new HostBuilder();
            builder.UseSerilog(SerilogLogger, dispose: true);

            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithManagedServiceIdentityWithOptions(VaultUri, MsiConnectionString,
                configureOptions: options => options.TrackDependency = trackDependency));

            // Assert
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
                AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
            }
            
            AssertTrackedAzureKeyVaultDependency(expectedTrackedDependencies);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentity_GetSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(VaultUri, MsiConnectionString);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var keyName = "UnknownSecretName";
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentityWithOptions(
                    VaultUri, MsiConnectionString, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            string appendedKeyName = "Test-" + TestSecretName;
            AssertNotNullSecret(await provider.GetSecretAsync(appendedKeyName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(appendedKeyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentityWithOptions(
                    VaultUri, MsiConnectionString, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
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
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentity_GetSecretSucceeds()
        {
            // Arrange

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(VaultUri, connectionString: MsiConnectionString, cacheConfiguration: cacheConfiguration);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
            Assert.True(cacheConfiguration.IsCalled);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentity_GetSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(VaultUri, connectionString: MsiConnectionString, cacheConfiguration: cacheConfiguration);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var keyName = "UnknownSecretName";
            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(keyName));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentityWithOptions(
                    VaultUri, connectionString: MsiConnectionString, cacheConfiguration: cacheConfiguration, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            string appendedKeyName = "Test-" + TestSecretName;
            AssertNotNullSecret(await provider.GetSecretAsync(appendedKeyName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(appendedKeyName));
            Assert.True(cacheConfiguration.IsCalled);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentityWithOptions(
                    VaultUri, connectionString: MsiConnectionString, cacheConfiguration: cacheConfiguration, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
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
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, "wrong-app-id", "wrong-access-key");
            });

            // Assert
           using  IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var exceptionFromSecretAsync = await Assert.ThrowsAsync<AdalServiceException>(() => provider.GetSecretAsync(TestSecretName));
            var exceptionFromRawSecretAsync = await Assert.ThrowsAsync<AdalServiceException>(() => provider.GetRawSecretAsync(TestSecretName));
            var errorCode = "unauthorized_client";
            Assert.Equal(errorCode, exceptionFromSecretAsync.ErrorCode);
            Assert.Equal(errorCode, exceptionFromRawSecretAsync.ErrorCode);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithWrongUnauthorizedServicePrincipal_Throws()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:UnauthorizedServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:UnauthorizedServicePrincipal:AccessKey");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, applicationId, clientKey);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var exceptionFromSecretAsync = await Assert.ThrowsAsync<KeyVaultErrorException>(() => provider.GetSecretAsync(TestSecretName));
            var exceptionFromRawSecretAsync = await Assert.ThrowsAsync<KeyVaultErrorException>(() => provider.GetRawSecretAsync(TestSecretName));
            Assert.Equal(HttpStatusCode.Forbidden, exceptionFromSecretAsync.Response.StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, exceptionFromRawSecretAsync.Response.StatusCode);
        }
        
        [Fact]
        public async Task AddAzureKeyVaultWithTenantSimple_WithServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, ClientId, ClientSecret);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            AssertNotNullSecret(provider.GetSecret(TestSecretName));
            AssertNotNullSecret(provider.GetRawSecret(TestSecretName));
            AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            string prefix = "Test-";
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    VaultUri,
                    TenantId,
                    ClientId,
                    ClientSecret,
                    configureOptions: _ => { },
                    name: "Azure Key Vault",
                    mutateSecretName: secretName => secretName.Remove(0, prefix.Length));
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            string appendedKeyName = prefix + TestSecretName;
            AssertNotNullSecret(provider.GetSecret(appendedKeyName));
            AssertNotNullSecret(provider.GetRawSecret(appendedKeyName));
            AssertNotNullSecret(await provider.GetSecretAsync(appendedKeyName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(appendedKeyName));
        }

        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 2)]
        public async Task AddAzureKeyVaultWithTenantWithDependencyTracking_WithServicePrincipal_GetSecretSucceeds(bool trackDependency, int expectedTrackedDependencies)
        {
            // Arrange
            var builder = new HostBuilder();
            builder.UseSerilog(SerilogLogger, dispose: true);

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, ClientId, ClientSecret,
                    configureOptions: options => options.TrackDependency = trackDependency, name: null, mutateSecretName: null);
            });

            // Assert
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
                AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
            }

            AssertTrackedAzureKeyVaultDependency(expectedTrackedDependencies);
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithServicePrincipal_GetSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, ClientId, ClientSecret, configureOptions: null, name: null, mutateSecretName: null);
            });
            
            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var keyName = "UnknownSecretName";
            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(keyName));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }

        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 2)]
        public async Task AddAzureKeyVaultWithTenantWithDependencyTracking_WithServicePrincipal_GetSecretFails(bool trackDependency, int expectedTrackedDependencies)
        {
            // Arrange
            var builder = new HostBuilder();
            builder.UseSerilog(SerilogLogger, dispose: true);

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, ClientId, ClientSecret,
                    configureOptions: options => options.TrackDependency = trackDependency, name: null, mutateSecretName: null);
            });
            
            // Assert
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();
                
                var keyName = "UnknownSecretName";
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(keyName));
            }
            
            AssertTrackedAzureKeyVaultDependency(expectedTrackedDependencies);
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithServicePrincipalToDots_GetsSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    VaultUri, TenantId, ClientId, ClientSecret, 
                    mutateSecretName: secretName => secretName.Remove(0, 5),
                    name: null,
                    configureOptions: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            string appendedKeyName = "Test-" + TestSecretName;
            AssertNotNullSecret(provider.GetSecret(appendedKeyName));
            AssertNotNullSecret(provider.GetRawSecret(appendedKeyName));
            AssertNotNullSecret(await provider.GetSecretAsync(appendedKeyName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(appendedKeyName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithServicePrincipalWrongMutation_GetsSecretsFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    VaultUri, TenantId, ClientId, ClientSecret, 
                    mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName,
                    configureOptions: null,
                    name: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(TestSecretName));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(TestSecretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(TestSecretName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithCachedServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, ClientId, ClientSecret, allowCaching: true, configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            AssertNotNullSecret(provider.GetSecret(TestSecretName));
            AssertNotNullSecret(provider.GetRawSecret(TestSecretName));
            AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithCachedServicePrincipal_GetSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, ClientId, ClientSecret, allowCaching: true, configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var keyName = "UnknownSecretName";
            Assert.Throws<SecretNotFoundException>(() => provider.GetSecret(keyName));
            Assert.Throws<SecretNotFoundException>(() => provider.GetRawSecret(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetRawSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithCachedServicePrincipalRemovesPrefix_GetsSecretsSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    VaultUri, TenantId, ClientId, ClientSecret, allowCaching: true, 
                    mutateSecretName: secretName => secretName.Remove(0, 5),
                    configureOptions: null,
                    name: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            string appendedKeyName = "Test-" + TestSecretName;
            AssertNotNullSecret(provider.GetSecret(appendedKeyName));
            AssertNotNullSecret(provider.GetRawSecret(appendedKeyName));
            AssertNotNullSecret(await provider.GetSecretAsync(appendedKeyName));
            AssertNotNullSecret(await provider.GetRawSecretAsync(appendedKeyName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithCachedServicePrincipalWrongMutation_GetsSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    VaultUri, TenantId, ClientId, ClientSecret, allowCaching: true, 
                    mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName,
                    configureOptions: null,
                    name: null);
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
        public async Task AddAzureKeyVault_WithManagedIdentity_GetSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddAzureKeyVaultWithManagedIdentity(VaultUri, ClientId));

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            {
                using IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                AssertNotNullSecret(provider.GetSecret(TestSecretName));
                AssertNotNullSecret(provider.GetRawSecret(TestSecretName));
                AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
                AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
            }
        }

        [Fact]
        public async Task AddAzureKeyVaultSimple_WithManagedIdentity_GetSecretSucceeds()
        {
            // Arrange
            string prefix = "Test-";
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri, ClientId,
                    configureOptions: _ => { },
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
                AssertNotNullSecret(provider.GetSecret(appendedKeyName));
                AssertNotNullSecret(provider.GetRawSecret(appendedKeyName));
                AssertNotNullSecret(await provider.GetSecretAsync(appendedKeyName));
                AssertNotNullSecret(await provider.GetRawSecretAsync(appendedKeyName));
            }
        }

        [Theory]
        [InlineData(false, 0)]
        [InlineData(true, 2)]
        public async Task AddAzureKeyVaultWithDependencyTracking_WithManagedIdentity_GetSecretSucceeds(bool trackDependency, int expectedTrackedDependencies)
        {
            // Arrange
            var builder = new HostBuilder();
            builder.UseSerilog(SerilogLogger, dispose: true);

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(VaultUri, ClientId, configureOptions: options => options.TrackDependency = trackDependency, name: null, mutateSecretName: null);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, TenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, ClientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, ClientSecret))
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
                AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
            }

            AssertTrackedAzureKeyVaultDependency(expectedTrackedDependencies);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri, ClientId, 
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
                AssertNotNullSecret(provider.GetSecret(appendedKeyName));
                AssertNotNullSecret(provider.GetRawSecret(appendedKeyName));
                AssertNotNullSecret(await provider.GetSecretAsync(appendedKeyName));
                AssertNotNullSecret(await provider.GetRawSecretAsync(appendedKeyName));
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri, ClientId, 
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
            builder.UseSerilog(SerilogLogger, dispose: true);

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    VaultUri, ClientId,
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
            builder.ConfigureSecretStore((_, stores) =>
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

                AssertNotNullSecret(provider.GetSecret(TestSecretName));
                AssertNotNullSecret(provider.GetRawSecret(TestSecretName));
                AssertNotNullSecret(await provider.GetSecretAsync(TestSecretName));
                AssertNotNullSecret(await provider.GetRawSecretAsync(TestSecretName));
                Assert.True(cacheConfiguration.IsCalled); 
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedIdentity_GetSecretFails()
        {
            // Arrange
            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
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

                var keyName = "UnknownSecretName";
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
            builder.ConfigureSecretStore((_, stores) =>
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
                AssertNotNullSecret(provider.GetSecret(appendedKeyName));
                AssertNotNullSecret(provider.GetRawSecret(appendedKeyName));
                AssertNotNullSecret(await provider.GetSecretAsync(appendedKeyName));
                AssertNotNullSecret(await provider.GetRawSecretAsync(appendedKeyName));
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
            builder.ConfigureSecretStore((_, stores) =>
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
        public async Task AddAzureKeyVaultWithTenant_WithWrongServicePrincipalCredentials_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, "wrong-app-id", "wrong-access-key", configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.Throws<AuthenticationFailedException>(() => provider.GetSecret(TestSecretName));
            Assert.Throws<AuthenticationFailedException>(() => provider.GetRawSecret(TestSecretName));
            await Assert.ThrowsAsync<AuthenticationFailedException>(() => provider.GetSecretAsync(TestSecretName));
            await Assert.ThrowsAsync<AuthenticationFailedException>(() => provider.GetRawSecretAsync(TestSecretName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithWrongUnauthorizedServicePrincipal_Throws()
        {
            // Arrange
            var builder = new HostBuilder();
            builder.UseSerilog(SerilogLogger, dispose: true);
            string clientId = Configuration.GetRequiredValue("Arcus:UnauthorizedServicePrincipal:ApplicationId");
            string clientSecret = Configuration.GetRequiredValue("Arcus:UnauthorizedServicePrincipal:AccessKey");

            // Act
            builder.ConfigureSecretStore((_, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(VaultUri, TenantId, clientId, clientSecret, configureOptions: null, name: null, mutateSecretName: null);
            });

            // Assert
            using IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Assert.All(new[]
            {
                Assert.Throws<RequestFailedException>(() => provider.GetSecret(TestSecretName)),
                Assert.Throws<RequestFailedException>(() => provider.GetRawSecret(TestSecretName)),
                await Assert.ThrowsAsync<RequestFailedException>(() => provider.GetSecretAsync(TestSecretName)),
                await Assert.ThrowsAsync<RequestFailedException>(() => provider.GetRawSecretAsync(TestSecretName))
            }, exception => Assert.Equal(StatusCodes.Status403Forbidden, exception.Status));
        }

        private void AssertTrackedAzureKeyVaultDependency(int expectedTrackedDependencyCount)
        {
            int actualTrackedDependencyCount = InMemoryLogSink.CurrentLogEmits.Count(ev => ev.MessageTemplate.Text.Contains("Dependency"));

            Assert.Equal(expectedTrackedDependencyCount, actualTrackedDependencyCount);
        }
    }
}
