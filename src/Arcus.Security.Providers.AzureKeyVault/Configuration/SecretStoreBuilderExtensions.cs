using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using GuardNet;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

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
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> or <paramref name="clientId"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            X509Certificate2 certificate,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the application requesting the authentication token that has read permissions on the Azure Key Vault to add a secret provider to the secret store");
            Guard.NotNull(certificate, nameof(certificate), "Requires a certificate that is being used as credential on the Azure Key Vault to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new CertificateBasedAuthentication(clientId, certificate),
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching,
                mutateSecretName);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> or <paramref name="clientId"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            X509Certificate2 certificate,
            ICacheConfiguration cacheConfiguration,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the application requesting the authentication token that has read permissions on the Azure Key Vault to add a secret provider to the secret store");
            Guard.NotNull(certificate, nameof(certificate), "Requires a certificate that is being used as credential on the Azure Key Vault to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new CertificateBasedAuthentication(clientId, certificate),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration: cacheConfiguration,
                mutateSecretName: mutateSecretName);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="connectionString">The connection string to use to authenticate, if applicable.</param>
        /// <param name="azureADInstance">The azure AD instance to use to authenticate, if applicable.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string connectionString = null,
            string azureADInstance = null,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new ManagedServiceIdentityAuthentication(connectionString, azureADInstance),
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching,
                mutateSecretName);
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
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            ICacheConfiguration cacheConfiguration,
            string connectionString = null,
            string azureADInstance = null,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new ManagedServiceIdentityAuthentication(connectionString, azureADInstance),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration,
                mutateSecretName);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            string clientKey,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientKey, nameof(clientKey), "Requires a non-blank client access key of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add to the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new ServicePrincipalAuthentication(clientId, clientKey),
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching,
                mutateSecretName);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            string clientKey,
            ICacheConfiguration cacheConfiguration,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNullOrWhitespace(rawVaultUri, nameof(rawVaultUri), "Requires a non-blank URI of the Azure Key Vault instance to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientId, nameof(clientId), "Requires a non-blank client ID of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add the secret provider to the secret store");
            Guard.NotNullOrWhitespace(clientKey, nameof(clientKey), "Requires a non-blank client access key of the Service Principal that has permissions to read the secrets in the Azure Key Vault to add to the secret provider to the secret store");

            return AddAzureKeyVault(
                builder,
                new ServicePrincipalAuthentication(clientId, clientKey),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration: cacheConfiguration,
                mutateSecretName: mutateSecretName);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="authentication">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="authentication"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration,
            bool allowCaching = false,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNull(authentication, nameof(authentication), "Requires an Azure Key Vault authentication instance to add the secret provider to the secret store");
            Guard.NotNull(configuration, nameof(configuration), "Requires an Azure Key Vault configuration instance to add the secret provider to the secret store");

            ICacheConfiguration cacheConfiguration = allowCaching ? new CacheConfiguration() : null;
            return AddAzureKeyVault(builder, authentication, configuration, cacheConfiguration, mutateSecretName);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="authentication">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="authentication"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration,
            ICacheConfiguration cacheConfiguration,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Azure Key Vault secret provider");
            Guard.NotNull(authentication, nameof(authentication), "Requires an Azure Key Vault authentication instance to add the secret provider to the secret store");
            Guard.NotNull(configuration, nameof(configuration), "Requires an Azure Key Vault configuration instance to add the secret provider to the secret store");

            // Thrown during failure with Active Directory authentication.
            builder.AddCriticalException<AdalServiceException>();
            
            // Thrown during calling invalid Key Vault URI.
            builder.AddCriticalException<HttpRequestException>(exception =>
            {
                // Make sure it was thrown from this namespace.
                return exception.Source == "Microsoft.Rest.ClientRuntime"
                       && exception.Message == "No such host is known.";
            });

            // Thrown during failure with Key Vault authorization.
            builder.AddCriticalException<KeyVaultErrorException>(exception =>
            {
                return exception.Response.StatusCode == HttpStatusCode.Forbidden
                       || exception.Response.StatusCode == HttpStatusCode.Unauthorized
                       || exception.Response.StatusCode == HttpStatusCode.BadRequest;
            });

            var keyVaultSecretProvider = new KeyVaultSecretProvider(authentication, configuration);

            if (cacheConfiguration is null)
            {
                return builder.AddProvider(keyVaultSecretProvider, mutateSecretName);
            }

            var cachedSecretProvider = new CachedSecretProvider(keyVaultSecretProvider, cacheConfiguration);
            return builder.AddProvider(cachedSecretProvider, mutateSecretName);
        }
    }
}
