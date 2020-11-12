using System;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Azure;
using Azure.Core;
using Azure.Identity;
using GuardNet;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

#pragma warning disable 618

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Extensions on the <see cref="SecretStoreBuilder"/> to provide easy addition the Azure Key Vault secrets in the secret store.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithCertificate) + " overload with the tenant ID instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            X509Certificate2 certificate,
            bool allowCaching = false)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the application requesting the authentication token that has read permissions on the Azure Key Vault to add a secret provider to the secret store");
            Guard.NotNull(certificate, nameof(certificate), "Requires a certificate that is being used as credential on the Azure Key Vault to add the secret provider to the secret store");

            return AddAzureKeyVaultWithCertificateWithOptions(builder, rawVaultUri, clientId, certificate, mutateSecretName: null, allowCaching: allowCaching);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> or <paramref name="clientId"/> is blank.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithCertificate) + " overload with the tenant ID instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificateWithOptions(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            X509Certificate2 certificate,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the application requesting the authentication token that has read permissions on the Azure Key Vault to add a secret provider to the secret store");
            Guard.NotNull(certificate, nameof(certificate), "Requires a certificate that is being used as credential on the Azure Key Vault to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                serviceProvider =>
                {
                    var logger = serviceProvider.GetService<ILogger<CertificateBasedAuthentication>>();
                    return new CertificateBasedAuthentication(clientId, certificate, logger);
                },
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching,
                mutateSecretName,
                configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) ID of the client or application.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> or <paramref name="clientId"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            X509Certificate2 certificate,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(tenantId, nameof(tenantId), "Requires a non-blank tenant ID of the directory where the client or application is located");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the application requesting the authentication token that has read permissions on the Azure Key Vault to add a secret provider to the secret store");
            Guard.NotNull(certificate, nameof(certificate), "Requires a certificate that is being used as credential on the Azure Key Vault to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new ClientCertificateCredential(tenantId, clientId, certificate),
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching,
                mutateSecretName,
                configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> or <paramref name="clientId"/> is blank.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithCertificate) + " overload with the tenant ID instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            X509Certificate2 certificate,
            ICacheConfiguration cacheConfiguration)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the application requesting the authentication token that has read permissions on the Azure Key Vault to add a secret provider to the secret store");
            Guard.NotNull(certificate, nameof(certificate), "Requires a certificate that is being used as credential on the Azure Key Vault to add the secret provider to the secret store");

            return AddAzureKeyVaultWithCertificateWithOptions(builder, rawVaultUri, clientId, certificate, configureOptions: null, mutateSecretName: null, cacheConfiguration: cacheConfiguration);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> or <paramref name="clientId"/> is blank.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithCertificate) + " overload with the tenant ID instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificateWithOptions(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            X509Certificate2 certificate,
            ICacheConfiguration cacheConfiguration,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the application requesting the authentication token that has read permissions on the Azure Key Vault to add a secret provider to the secret store");
            Guard.NotNull(certificate, nameof(certificate), "Requires a certificate that is being used as credential on the Azure Key Vault to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                serviceProvider =>
                {
                    var logger = serviceProvider.GetService<ILogger<CertificateBasedAuthentication>>();
                    return new CertificateBasedAuthentication(clientId, certificate, logger);
                },
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration: cacheConfiguration,
                mutateSecretName: mutateSecretName);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) ID of the client or application.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> or <paramref name="clientId"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            X509Certificate2 certificate,
            ICacheConfiguration cacheConfiguration,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(tenantId, nameof(tenantId), "Requires a non-blank tenant ID of the directory where the client or application is located");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the application requesting the authentication token that has read permissions on the Azure Key Vault to add a secret provider to the secret store");
            Guard.NotNull(certificate, nameof(certificate), "Requires a certificate that is being used as credential on the Azure Key Vault to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new ClientCertificateCredential(tenantId, clientId, certificate),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration,
                mutateSecretName,
                configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="connectionString">The connection string to use to authenticate, if applicable.</param>
        /// <param name="azureADInstance">The azure AD instance to use to authenticate, if applicable.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithManagedIdentity) + " overload with the 'clientId' instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string connectionString = null,
            string azureADInstance = null,
            bool allowCaching = false)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");

            return AddAzureKeyVaultWithManagedServiceIdentityWithOptions(builder, rawVaultUri, connectionString, azureADInstance, mutateSecretName: null, configureOptions: null, allowCaching: allowCaching);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="connectionString">The connection string to use to authenticate, if applicable.</param>
        /// <param name="azureADInstance">The azure AD instance to use to authenticate, if applicable.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithManagedIdentity) + " overload with the 'clientId' instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentityWithOptions(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string connectionString = null,
            string azureADInstance = null,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                serviceProvider =>
                {
                    var logger = serviceProvider.GetService<ILogger<ManagedServiceIdentityAuthentication>>();
                    return new ManagedServiceIdentityAuthentication(connectionString, azureADInstance, logger);
                },
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching,
                mutateSecretName);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">
        ///     The client id to authenticate for a user assigned managed identity.
        ///     More information on user assigned managed identities can be found here: https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#how-a-user-assigned-managed-identity-works-with-an-azure-vm</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId = null,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new ChainedTokenCredential(new ManagedIdentityCredential(clientId), new EnvironmentCredential()),
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching,
                mutateSecretName,
                configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="connectionString">The connection string to use to authenticate, if applicable.</param>
        /// <param name="azureADInstance">The azure AD instance to use to authenticate, if applicable.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithManagedIdentity) + " overload with the 'clientId' instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            ICacheConfiguration cacheConfiguration,
            string connectionString = null,
            string azureADInstance = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");

            return AddAzureKeyVaultWithManagedServiceIdentityWithOptions(builder, rawVaultUri, cacheConfiguration, connectionString, azureADInstance, mutateSecretName: null, configureOptions: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="connectionString">The connection string to use to authenticate, if applicable.</param>
        /// <param name="azureADInstance">The azure AD instance to use to authenticate, if applicable.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithManagedIdentity) + " overload with the 'clientId' instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentityWithOptions(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            ICacheConfiguration cacheConfiguration,
            string connectionString = null,
            string azureADInstance = null,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                serviceProvider =>
                {
                    var logger = serviceProvider.GetService<ILogger<ManagedServiceIdentityAuthentication>>();
                    return new ManagedServiceIdentityAuthentication(connectionString, azureADInstance, logger);
                },
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration,
                mutateSecretName,
                configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">
        ///     The client id to authenticate for a user assigned managed identity.
        ///     More information on user assigned managed identities can be found here: https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#how-a-user-assigned-managed-identity-works-with-an-azure-vm</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            ICacheConfiguration cacheConfiguration,
            string clientId = null,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new ChainedTokenCredential(new ManagedIdentityCredential(clientId), new EnvironmentCredential()),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration,
                mutateSecretName,
                configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithServicePrincipal) + " overload with the 'tenantId' instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            string clientKey,
            bool allowCaching = false)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientKey, nameof(clientKey), "Requires a non-blank client access key of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add to the secret provider to the secret store");

            return AddAzureKeyVaultWithServicePrincipalWithOptions(builder, rawVaultUri, clientId, clientKey, mutateSecretName: null, configureOptions: null, allowCaching: allowCaching);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithServicePrincipal) + " overload with the 'tenantId' instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipalWithOptions(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            string clientKey,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientKey, nameof(clientKey), "Requires a non-blank client access key of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add to the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                serviceProvider =>
                {
                    var logger = serviceProvider.GetService<ILogger<ServicePrincipalAuthentication>>();
                    return new ServicePrincipalAuthentication(clientId, clientKey, logger);
                },
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching,
                mutateSecretName,
                configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) Id of the service principal.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            string clientKey,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(tenantId, nameof(tenantId), "Requires a non-blank tenant ID of the directory where the Service Principal is located");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientKey, nameof(clientKey), "Requires a non-blank client access key of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add to the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new ClientSecretCredential(tenantId, clientId, clientKey), 
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching,
                mutateSecretName,
                configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithServicePrincipal) + " overload with the 'tenantId' instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            string clientKey,
            ICacheConfiguration cacheConfiguration)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientKey, nameof(clientKey), "Requires a non-blank client access key of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add to the secret provider to the secret store");

            return AddAzureKeyVaultWithServicePrincipalWithOptions(builder, rawVaultUri, clientId, clientKey, configureOptions: null, mutateSecretName: null, cacheConfiguration: cacheConfiguration);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVaultWithServicePrincipal) + " overload with the 'tenantId' instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipalWithOptions(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            string clientKey,
            ICacheConfiguration cacheConfiguration,
            Action<KeyVaultOptions> configureOptions = null,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientKey, nameof(clientKey), "Requires a non-blank client access key of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add to the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                serviceProvider =>
                {
                    var logger = serviceProvider.GetService<ILogger<ServicePrincipalAuthentication>>();
                    return new ServicePrincipalAuthentication(clientId, clientKey, logger);
                },
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration: cacheConfiguration,
                mutateSecretName: mutateSecretName,
                configureOptions: configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) Id of the service principal.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            string clientKey,
            ICacheConfiguration cacheConfiguration,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(tenantId, nameof(tenantId), "Requires a non-blank tenant ID of the directory where the Service Principal is located");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientKey, nameof(clientKey), "Requires a non-blank client access key of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add to the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new ClientSecretCredential(tenantId, clientId, clientKey), 
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration,
                mutateSecretName,
                configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="authentication">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="authentication"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVault) + " overload with the 'TokenCredential' instead")]
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration,
            bool allowCaching = false)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNull(authentication, nameof(authentication), "Requires an Azure Key Vault authentication instance to add the secret provider to the secret store");
            Guard.NotNull(configuration, nameof(configuration), "Requires an Azure Key Vault configuration instance to add the secret provider to the secret store");

            return AddAzureKeyVaultWithOptions(builder, authentication, configuration, mutateSecretName: null, configureOptions: null, allowCaching: allowCaching);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="authentication">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="authentication"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVault) + " overload with the 'TokenCredential' instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithOptions(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNull(authentication, nameof(authentication), "Requires an Azure Key Vault authentication instance to add the secret provider to the secret store");
            Guard.NotNull(configuration, nameof(configuration), "Requires an Azure Key Vault configuration instance to add the secret provider to the secret store");

            return AddAzureKeyVault(builder, serviceProvider => authentication, configuration, allowCaching, mutateSecretName, configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="authentication">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="authentication"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVault) + " overload with the 'TokenCredential' instead")]
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration,
            ICacheConfiguration cacheConfiguration)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNull(authentication, nameof(authentication), "Requires an Azure Key Vault authentication instance to add the secret provider to the secret store");
            Guard.NotNull(configuration, nameof(configuration), "Requires an Azure Key Vault configuration instance to add the secret provider to the secret store");

            return AddAzureKeyVaultWithOptions(builder, authentication, configuration, configureOptions: null, mutateSecretName: null, cacheConfiguration: cacheConfiguration);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="authentication">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="authentication"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
        [Obsolete("Use the " + nameof(AddAzureKeyVault) + " overload with the 'TokenCredential' instead")]
        public static SecretStoreBuilder AddAzureKeyVaultWithOptions(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration,
            ICacheConfiguration cacheConfiguration,
            Action<KeyVaultOptions> configureOptions = null,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNull(authentication, nameof(authentication), "Requires an Azure Key Vault authentication instance to add the secret provider to the secret store");
            Guard.NotNull(configuration, nameof(configuration), "Requires an Azure Key Vault configuration instance to add the secret provider to the secret store");

            return AddAzureKeyVault(builder, serviceProvider => authentication, configuration, cacheConfiguration, mutateSecretName);
        }

        private static SecretStoreBuilder AddAzureKeyVault(
            SecretStoreBuilder builder,
            Func<IServiceProvider, IKeyVaultAuthentication> createAuthentication,
            IKeyVaultConfiguration configuration,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            ICacheConfiguration cacheConfiguration = allowCaching ? new CacheConfiguration() : null;
            return AddAzureKeyVault(builder, createAuthentication, configuration, cacheConfiguration, mutateSecretName, configureOptions);
        }

        private static SecretStoreBuilder AddAzureKeyVault(
            SecretStoreBuilder builder,
            Func<IServiceProvider, IKeyVaultAuthentication> createAuthentication,
            IKeyVaultConfiguration configuration,
            ICacheConfiguration cacheConfiguration,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            // Thrown by our own authentication implementations when there's a problem with authentication to Azure Key Vault.
            builder.AddCriticalException<AuthenticationException>();

            // Thrown during failure with Active Directory authentication.
            builder.AddCriticalException<AdalServiceException>();
            
            // Thrown during failure with Key Vault authorization.
            builder.AddCriticalException<KeyVaultErrorException>(exception =>
            {
                return exception.Response.StatusCode == HttpStatusCode.Forbidden
                       || exception.Response.StatusCode == HttpStatusCode.Unauthorized
                       || exception.Response.StatusCode == HttpStatusCode.BadRequest;
            });

            return builder.AddProvider(serviceProvider =>
            {
                var options = new KeyVaultOptions();
                configureOptions?.Invoke(options);

                IKeyVaultAuthentication authentication = createAuthentication(serviceProvider);
                var logger = serviceProvider.GetService<ILogger<KeyVaultSecretProvider>>();

                var keyVaultSecretProvider = new KeyVaultSecretProvider(authentication, configuration, options, logger);
                
                if (cacheConfiguration is null)
                {
                    return keyVaultSecretProvider;
                }
                
                return new CachedSecretProvider(keyVaultSecretProvider, cacheConfiguration);
            }, mutateSecretName);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="tokenCredential"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            TokenCredential tokenCredential,
            IKeyVaultConfiguration configuration,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNull(tokenCredential, nameof(tokenCredential), "Requires an Azure Key Vault authentication instance to add the secret provider to the secret store");
            Guard.NotNull(configuration, nameof(configuration), "Requires an Azure Key Vault configuration instance to add the secret provider to the secret store");

            return AddAzureKeyVault(builder, tokenCredential, configuration, cacheConfiguration: null, mutateSecretName: mutateSecretName, configureOptions: configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="tokenCredential"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            TokenCredential tokenCredential,
            IKeyVaultConfiguration configuration,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNull(tokenCredential, nameof(tokenCredential), "Requires an Azure Key Vault authentication instance to add the secret provider to the secret store");
            Guard.NotNull(configuration, nameof(configuration), "Requires an Azure Key Vault configuration instance to add the secret provider to the secret store");

            ICacheConfiguration cacheConfiguration = allowCaching ? new CacheConfiguration() : null;
            return AddAzureKeyVault(builder, tokenCredential, configuration, cacheConfiguration, mutateSecretName, configureOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="tokenCredential"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            TokenCredential tokenCredential,
            IKeyVaultConfiguration configuration,
            ICacheConfiguration cacheConfiguration,
            Func<string, string> mutateSecretName = null,
            Action<KeyVaultOptions> configureOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNull(tokenCredential, nameof(tokenCredential), "Requires an Azure Key Vault authentication instance to add the secret provider to the secret store");
            Guard.NotNull(configuration, nameof(configuration), "Requires an Azure Key Vault configuration instance to add the secret provider to the secret store");

            // Thrown during failure with Key Vault authorization.
            builder.AddCriticalException<RequestFailedException>(exception =>
            {
                return exception.Status == 403 || exception.Status == 401 || exception.Status == 400;
            });

            builder.AddCriticalException<CredentialUnavailableException>();
            builder.AddCriticalException<AuthenticationFailedException>();

            return builder.AddProvider(serviceProvider =>
            {
                var logger = serviceProvider.GetService<ILogger<KeyVaultSecretProvider>>();
                var options = new KeyVaultOptions();
                configureOptions?.Invoke(options);

                var keyVaultSecretProvider = new KeyVaultSecretProvider(tokenCredential, configuration, options, logger);
                if (cacheConfiguration is null)
                {
                    return keyVaultSecretProvider;
                }

                var cachedSecretProvider = new CachedSecretProvider(keyVaultSecretProvider, cacheConfiguration);
                return cachedSecretProvider;
            }, mutateSecretName);
        }
    }
}
