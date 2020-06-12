using System.Security.Cryptography.X509Certificates;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using GuardNet;

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
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            X509Certificate2 certificate,
            bool allowCaching = false)
        {
            Guard.NotNull(rawVaultUri, nameof(rawVaultUri));
            Guard.NotNull(clientId, nameof(clientId));
            Guard.NotNull(certificate, nameof(certificate));

            return AddAzureKeyVault(
                builder,
                new CertificateBasedAuthentication(clientId, certificate),
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            X509Certificate2 certificate,
            ICacheConfiguration cacheConfiguration)
        {
            Guard.NotNull(rawVaultUri, nameof(rawVaultUri));
            Guard.NotNull(clientId, nameof(clientId));
            Guard.NotNull(certificate, nameof(certificate));

            return AddAzureKeyVault(
                builder,
                new CertificateBasedAuthentication(clientId, certificate),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration: cacheConfiguration);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="connectionString">The connection string to use to authenticate, if applicable.</param>
        /// <param name="azureADInstance">The azure AD instance to use to authenticate, if applicable.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string connectionString = null,
            string azureADInstance = null,
            bool allowCaching = false)
        {
            Guard.NotNull(rawVaultUri, nameof(rawVaultUri));

            return AddAzureKeyVault(
                builder,
                new ManagedServiceIdentityAuthentication(connectionString, azureADInstance),
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            ICacheConfiguration cacheConfiguration)
        {
            Guard.NotNull(rawVaultUri, nameof(rawVaultUri));

            return AddAzureKeyVault(
                builder,
                new ManagedServiceIdentityAuthentication(),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="connectionString">The connection string to use to authenticate, if applicable.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string connectionString,
            ICacheConfiguration cacheConfiguration)
        {
            Guard.NotNull(rawVaultUri, nameof(rawVaultUri));

            return AddAzureKeyVault(
                builder,
                new ManagedServiceIdentityAuthentication(connectionString, azureAdInstance: null),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="connectionString">The connection string to use to authenticate, if applicable.</param>
        /// <param name="azureADInstance">The azure AD instance to use to authenticate, if applicable.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string connectionString,
            string azureADInstance,
            ICacheConfiguration cacheConfiguration)
        {
            Guard.NotNull(rawVaultUri, nameof(rawVaultUri));

            return AddAzureKeyVault(
                builder,
                new ManagedServiceIdentityAuthentication(connectionString, azureADInstance),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            string clientKey,
            bool allowCaching = false)
        {
            Guard.NotNull(rawVaultUri, nameof(rawVaultUri));
            Guard.NotNullOrEmpty(clientId, nameof(clientId));
            Guard.NotNullOrEmpty(clientKey, nameof(clientKey));

            return AddAzureKeyVault(
                builder,
                new ServicePrincipalAuthentication(clientId, clientKey),
                new KeyVaultConfiguration(rawVaultUri),
                allowCaching);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            string clientKey,
            ICacheConfiguration cacheConfiguration)
        {
            Guard.NotNull(rawVaultUri, nameof(rawVaultUri));
            Guard.NotNullOrEmpty(clientId, nameof(clientId));
            Guard.NotNullOrEmpty(clientKey, nameof(clientKey));

            return AddAzureKeyVault(
                builder,
                new ServicePrincipalAuthentication(clientId, clientKey),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration: cacheConfiguration);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="authentication">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="allowCaching">The flag to indicate whether to include caching during secret retrieval in Azure key vault.</param>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration,
            bool allowCaching = false)
        {
            Guard.NotNull(builder, nameof(builder));
            Guard.NotNull(authentication, nameof(authentication));
            Guard.NotNull(configuration, nameof(configuration));

            return AddAzureKeyVault(builder, authentication, configuration, allowCaching ? new CacheConfiguration() : null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="authentication">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done.</param>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration,
            ICacheConfiguration cacheConfiguration)
        {
            Guard.NotNull(builder, nameof(builder));
            Guard.NotNull(authentication, nameof(authentication));
            Guard.NotNull(configuration, nameof(configuration));

            var keyVaultSecretProvider = new KeyVaultSecretProvider(authentication, configuration);

            if (cacheConfiguration != null)
            {
                var cachedSecretProvider = new CachedSecretProvider(keyVaultSecretProvider, cacheConfiguration);
                return builder.AddProvider(cachedSecretProvider);
            }

            return builder.AddProvider(keyVaultSecretProvider);
        }
    }
}
