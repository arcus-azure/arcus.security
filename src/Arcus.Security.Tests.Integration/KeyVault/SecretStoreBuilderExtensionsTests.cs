﻿using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Integration.Fixture;
using Azure;
using Azure.Identity;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
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

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, applicationId, clientKey);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipal_GetSecretFails()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = "UnknownSecretName";

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, applicationId, clientKey);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipalToDots_GetsSecretSucceeds()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, applicationId, clientKey, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Test-" + keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithServicePrincipalWrongMutation_GetsSecretsFails()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, applicationId, clientKey, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, applicationId, clientKey, allowCaching: true);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipal_GetSecretFails()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = "Unknown.Secret.Name";

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, applicationId, clientKey, allowCaching: true);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipalRemovesPrefix_GetsSecretsSucceeds()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, applicationId, clientKey, allowCaching: true, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Test-" + keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedServicePrincipalWrongMutation_GetsSecretFails()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, applicationId, clientKey, allowCaching: true, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentity_GetSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, connectionString));

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentity_GetSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = "UnknownSecretName";

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, connectionString);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(
                    keyVaultUri, connectionString, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Test-" + keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedServiceIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(
                    keyVaultUri, connectionString, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentity_GetSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, connectionString: connectionString, cacheConfiguration: cacheConfiguration);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
            Assert.True(cacheConfiguration.IsCalled);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentity_GetSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = "Unknown.Secret.Name";

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(keyVaultUri, connectionString: connectionString, cacheConfiguration: cacheConfiguration);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(
                    keyVaultUri, connectionString: connectionString, cacheConfiguration: cacheConfiguration, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Test-" + keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
            Assert.True(cacheConfiguration.IsCalled);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedServiceIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var connectionString = Configuration.GetValue<string>("Arcus:MSI:AzureServicesAuth:ConnectionString");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedServiceIdentity(
                    keyVaultUri, connectionString: connectionString, cacheConfiguration: cacheConfiguration, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithWrongServicePrincipalCredentials_Throws()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, "wrong-app-id", "wrong-access-key");
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var exception = await Assert.ThrowsAsync<AdalServiceException>(() => provider.GetSecretAsync(keyName));
            Assert.Equal("unauthorized_client", exception.ErrorCode);
        }

        [Fact]
        public async Task AddAzureKeyVault_WithWrongUnauthorizedServicePrincipal_Throws()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:UnauthorizedServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:UnauthorizedServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, applicationId, clientKey);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var exception = await Assert.ThrowsAsync<KeyVaultErrorException>(() => provider.GetSecretAsync(keyName));
            Assert.Equal(HttpStatusCode.Forbidden, exception.Response.StatusCode);
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            string tenantId = Configuration.GetTenantId();
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, tenantId, applicationId, clientKey);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithServicePrincipal_GetSecretFails()
        {
            // Arrange
            string tenantId = Configuration.GetTenantId();
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = "UnknownSecretName";

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, tenantId, applicationId, clientKey);
            });
            
            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithServicePrincipalToDots_GetsSecretSucceeds()
        {
            // Arrange
            string tenantId = Configuration.GetTenantId();
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, tenantId, applicationId, clientKey, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Test-" + keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithServicePrincipalWrongMutation_GetsSecretsFails()
        {
            // Arrange
            string tenantId = Configuration.GetTenantId();
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, tenantId, applicationId, clientKey, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithCachedServicePrincipal_GetSecretSucceeds()
        {
            // Arrange
            string tenantId = Configuration.GetTenantId();
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, tenantId, applicationId, clientKey, allowCaching: true);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync(keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithCachedServicePrincipal_GetSecretFails()
        {
            // Arrange
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            var keyName = "Unknown.Secret.Name";

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, tenantId, applicationId, clientKey, allowCaching: true);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithCachedServicePrincipalRemovesPrefix_GetsSecretsSucceeds()
        {
            // Arrange
            string tenantId = Configuration.GetTenantId();
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, tenantId, applicationId, clientKey, allowCaching: true, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            Secret secret = await provider.GetSecretAsync("Test-" + keyName);
            Assert.NotNull(secret);
            Assert.NotNull(secret.Value);
            Assert.NotNull(secret.Version);
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithCachedServicePrincipalWrongMutation_GetsSecretFails()
        {
            // Arrange
            string tenantId = Configuration.GetTenantId();
            string applicationId = Configuration.GetValue<string>("Arcus:ServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:ServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(
                    keyVaultUri, tenantId, applicationId, clientKey, allowCaching: true, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            await Assert.ThrowsAsync<SecretNotFoundException>(
                () => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedIdentity_GetSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            string clientId = Configuration.GetServicePrincipalClientId();
            var clientKey = Configuration.GetServicePrincipalClientSecret();
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddAzureKeyVaultWithManagedIdentity(keyVaultUri, clientId));

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientKey))
            {
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                Secret secret = await provider.GetSecretAsync(keyName);
                Assert.NotNull(secret);
                Assert.NotNull(secret.Value);
                Assert.NotNull(secret.Version); 
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            string clientId = Configuration.GetServicePrincipalClientId();
            string clientKey = Configuration.GetServicePrincipalClientSecret();
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    keyVaultUri, clientId, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientKey))
            {
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                Secret secret = await provider.GetSecretAsync("Test-" + keyName);
                Assert.NotNull(secret);
                Assert.NotNull(secret.Value);
                Assert.NotNull(secret.Version); 
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithManagedIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            string clientId = Configuration.GetServicePrincipalClientId();
            string clientKey = Configuration.GetServicePrincipalClientSecret();
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    keyVaultUri, clientId, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientKey))
            {
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                await Assert.ThrowsAsync<SecretNotFoundException>(
                    () => provider.GetSecretAsync(keyName)); 
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedIdentity_GetSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            string clientId = Configuration.GetServicePrincipalClientId();
            string clientKey = Configuration.GetServicePrincipalClientSecret();
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(keyVaultUri, cacheConfiguration, clientId);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientKey))
            {
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                Secret secret = await provider.GetSecretAsync(keyName);
                Assert.NotNull(secret);
                Assert.NotNull(secret.Value);
                Assert.NotNull(secret.Version);
                Assert.True(cacheConfiguration.IsCalled); 
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedIdentity_GetSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            string clientId = Configuration.GetServicePrincipalClientId();
            string clientKey = Configuration.GetServicePrincipalClientSecret();
            var keyName = "Unknown.Secret.Name";

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(keyVaultUri, clientId: clientId, cacheConfiguration: cacheConfiguration);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientKey))
            {
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                await Assert.ThrowsAsync<SecretNotFoundException>(
                    () => provider.GetSecretAsync(keyName)); 
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedIdentityRemovesPrefix_GetsSecretSucceeds()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            string clientId = Configuration.GetServicePrincipalClientId();
            string clientKey = Configuration.GetServicePrincipalClientSecret();
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    keyVaultUri, clientId: clientId, cacheConfiguration: cacheConfiguration, mutateSecretName: secretName => secretName.Remove(0, 5));
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientKey))
            {
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                Secret secret = await provider.GetSecretAsync("Test-" + keyName);
                Assert.NotNull(secret);
                Assert.NotNull(secret.Value);
                Assert.NotNull(secret.Version);
                Assert.True(cacheConfiguration.IsCalled); 
            }
        }

        [Fact]
        public async Task AddAzureKeyVault_WithCachedManagedIdentityWrongMutation_GetsSecretFails()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            string clientId = Configuration.GetServicePrincipalClientId();
            string clientKey = Configuration.GetServicePrincipalClientSecret();
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();
            var cacheConfiguration = new SpyCacheConfiguration();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithManagedIdentity(
                    keyVaultUri, clientId: clientId, cacheConfiguration: cacheConfiguration, mutateSecretName: secretName => "SOMETHING-WRONG-" + secretName);
            });

            // Assert
            using (TemporaryEnvironmentVariable.Create(Constants.AzureTenantIdEnvironmentVariable, tenantId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientIdVariable, clientId))
            using (TemporaryEnvironmentVariable.Create(Constants.AzureServicePrincipalClientSecretVariable, clientKey))
            {
                IHost host = builder.Build();
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                await Assert.ThrowsAsync<SecretNotFoundException>(() => provider.GetSecretAsync(keyName)); 
            }
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithWrongServicePrincipalCredentials_Throws()
        {
            // Arrange
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            string tenantId = Configuration.GetTenantId();
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, tenantId, "wrong-app-id", "wrong-access-key");
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var exception = await Assert.ThrowsAsync<AuthenticationFailedException>(() => provider.GetSecretAsync(keyName));
        }

        [Fact]
        public async Task AddAzureKeyVaultWithTenant_WithWrongUnauthorizedServicePrincipal_Throws()
        {
            // Arrange
            string tenantId = Configuration.GetTenantId();
            string applicationId = Configuration.GetValue<string>("Arcus:UnauthorizedServicePrincipal:ApplicationId");
            var clientKey = Configuration.GetValue<string>("Arcus:UnauthorizedServicePrincipal:AccessKey");
            var keyVaultUri = Configuration.GetValue<string>("Arcus:KeyVault:Uri");
            var keyName = Configuration.GetValue<string>("Arcus:KeyVault:TestKeyName");

            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) =>
            {
                stores.AddAzureKeyVaultWithServicePrincipal(keyVaultUri, tenantId, applicationId, clientKey);
            });

            // Assert
            IHost host = builder.Build();
            var provider = host.Services.GetRequiredService<ISecretProvider>();

            var exception = await Assert.ThrowsAsync<RequestFailedException>(() => provider.GetSecretAsync(keyName));
            Assert.Equal((int) HttpStatusCode.Forbidden, exception.Status);
        }
    }
}
