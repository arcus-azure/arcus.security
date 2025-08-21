using System;
using System.Security.Cryptography.X509Certificates;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Azure;
using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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
        /// <param name="tenantId">The Azure Active Directory tenant (directory) ID of the client or application.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="tenantId"/>, or <paramref name="clientId"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            X509Certificate2 certificate)
        {
            return AddAzureKeyVaultWithCertificate(
                builder,
                rawVaultUri,
                tenantId,
                clientId,
                certificate,
                cacheConfiguration: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) ID of the client or application.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="cacheConfiguration">
        ///     The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.
        /// </param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="tenantId"/>, or <paramref name="clientId"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            X509Certificate2 certificate,
            ICacheConfiguration cacheConfiguration)
        {
            return AddAzureKeyVaultWithCertificate(
                builder,
                rawVaultUri,
                tenantId,
                clientId,
                certificate,
                cacheConfiguration,
                configureOptions: null,
                name: null,
                mutateSecretName: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) ID of the client or application.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="cacheConfiguration">
        ///     The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.
        /// </param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="name">The unique name to register this Azure Key Vault provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="tenantId"/>, or <paramref name="clientId"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            X509Certificate2 certificate,
            ICacheConfiguration cacheConfiguration,
            Action<KeyVaultOptions> configureOptions,
            string name,
            Func<string, string> mutateSecretName)
        {
            return AddAzureKeyVaultWithCertificate(
                builder,
                rawVaultUri,
                tenantId,
                clientId,
                certificate,
                cacheConfiguration,
                configureOptions,
                options =>
                {
                    options.Name = name;
                    options.MutateSecretName = mutateSecretName;
                });
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses certificate authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) ID of the client or application.</param>
        /// <param name="clientId">The identifier of the application requesting the authentication token.</param>
        /// <param name="certificate">The certificate that is used as credential.</param>
        /// <param name="cacheConfiguration">
        ///     The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.
        /// </param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="configureProviderOptions"></param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="certificate"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="tenantId"/>, or <paramref name="clientId"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            X509Certificate2 certificate,
            ICacheConfiguration cacheConfiguration,
            Action<KeyVaultOptions> configureOptions,
            Action<SecretProviderOptions> configureProviderOptions)
        {
            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentException("Requires a non-blank client ID to authenticate the Azure Key vault secret provider with a certificate", nameof(clientId));
            }

            return AddAzureKeyVault(
                builder,
                new ClientCertificateCredential(tenantId, clientId, certificate),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration,
                configureOptions,
                configureProviderOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri)
        {
            return AddAzureKeyVaultWithManagedIdentity(
                builder,
                rawVaultUri,
                cacheConfiguration: null,
                clientId: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">
        ///     The optional client id to authenticate for a user assigned managed identity.
        ///     More information on user assigned managed identities can be found here: https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#how-a-user-assigned-managed-identity-works-with-an-azure-vm</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId)
        {
            return AddAzureKeyVaultWithManagedIdentity(
                builder,
                rawVaultUri,
                cacheConfiguration: null,
                clientId,
                configureOptions: null,
                name: null,
                mutateSecretName: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            ICacheConfiguration cacheConfiguration)
        {
            return AddAzureKeyVaultWithManagedIdentity(
                builder,
                rawVaultUri,
                cacheConfiguration,
                clientId: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">
        ///     The optional client id to authenticate for a user assigned managed identity.
        ///     More information on user assigned managed identities can be found here: https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#how-a-user-assigned-managed-identity-works-with-an-azure-vm</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            ICacheConfiguration cacheConfiguration,
            string clientId)
        {
            return AddAzureKeyVaultWithManagedIdentity(
                builder,
                rawVaultUri,
                cacheConfiguration,
                clientId,
                configureOptions: null,
                name: null,
                mutateSecretName: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="name">The unique name to register this Azure Key Vault provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            ICacheConfiguration cacheConfiguration,
            Action<KeyVaultOptions> configureOptions,
            string name,
            Func<string, string> mutateSecretName)
        {
            return AddAzureKeyVaultWithManagedIdentity(
                builder,
                rawVaultUri,
                cacheConfiguration,
                clientId: null,
                configureOptions: configureOptions,
                name: name,
                mutateSecretName: mutateSecretName);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">
        ///     The optional client id to authenticate for a user assigned managed identity.
        ///     More information on user assigned managed identities can be found here: https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#how-a-user-assigned-managed-identity-works-with-an-azure-vm</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="name">The unique name to register this Azure Key Vault provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            ICacheConfiguration cacheConfiguration,
            string clientId,
            Action<KeyVaultOptions> configureOptions,
            string name,
            Func<string, string> mutateSecretName)
        {
            return AddAzureKeyVaultWithManagedIdentity(
                builder,
                rawVaultUri,
                cacheConfiguration,
                clientId,
                configureOptions,
                options =>
                {
                    options.Name = name;
                    options.MutateSecretName = mutateSecretName;
                });
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses Managed Identity authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="clientId">
        ///     The optional client id to authenticate for a user assigned managed identity.
        ///     More information on user assigned managed identities can be found here: https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#how-a-user-assigned-managed-identity-works-with-an-azure-vm</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="configureProviderOptions">The optional additional options to configure the secret provider registration in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithManagedIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            ICacheConfiguration cacheConfiguration,
            string clientId,
            Action<KeyVaultOptions> configureOptions,
            Action<SecretProviderOptions> configureProviderOptions)
        {
            return AddAzureKeyVault(
                builder,
                new DefaultAzureCredential(new DefaultAzureCredentialOptions { ManagedIdentityClientId = clientId }),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration,
                configureOptions,
                configureProviderOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) Id of the service principal.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            string clientKey)
        {
            return AddAzureKeyVaultWithServicePrincipal(
                builder,
                rawVaultUri,
                tenantId,
                clientId,
                clientKey,
                cacheConfiguration: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) Id of the service principal.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="cacheConfiguration">
        ///     The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.
        /// </param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="rawVaultUri"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            string clientKey,
            ICacheConfiguration cacheConfiguration)
        {
            return AddAzureKeyVaultWithServicePrincipal(
                builder,
                rawVaultUri,
                tenantId,
                clientId,
                clientKey,
                cacheConfiguration,
                configureOptions: null,
                name: null,
                mutateSecretName: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) Id of the service principal.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="cacheConfiguration">
        ///     The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.
        /// </param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="name">The unique name to register this Azure Key Vault provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="rawVaultUri"/>, <paramref name="tenantId"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.
        /// </exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            string clientKey,
            ICacheConfiguration cacheConfiguration,
            Action<KeyVaultOptions> configureOptions,
            string name,
            Func<string, string> mutateSecretName)
        {
            return AddAzureKeyVaultWithServicePrincipal(
                builder,
                rawVaultUri,
                tenantId,
                clientId,
                clientKey,
                cacheConfiguration,
                configureOptions,
                options =>
                {
                    options.Name = name;
                    options.MutateSecretName = mutateSecretName;
                });
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source which uses client secret authentication.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <param name="tenantId">The Azure Active Directory tenant (directory) Id of the service principal.</param>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="cacheConfiguration">
        ///     The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.
        /// </param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="configureProviderOptions">The optional additional options to configure the secret provider registration in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="rawVaultUri"/>, <paramref name="tenantId"/>, <paramref name="clientId"/>, or <paramref name="clientKey"/> is blank.
        /// </exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string tenantId,
            string clientId,
            string clientKey,
            ICacheConfiguration cacheConfiguration,
            Action<KeyVaultOptions> configureOptions,
            Action<SecretProviderOptions> configureProviderOptions)
        {
            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentException("Requires a non-blank client ID to authenticate the Azure Key vault secret provider", nameof(clientId));
            }

            if (string.IsNullOrWhiteSpace(clientKey))
            {
                throw new ArgumentException("Requires a non-blank client secret to authenticate the Azure Key vault secret provider", nameof(clientKey));
            }

            return AddAzureKeyVault(
                builder,
                new ClientSecretCredential(tenantId, clientId, clientKey),
                new KeyVaultConfiguration(rawVaultUri),
                cacheConfiguration,
                configureOptions,
                configureProviderOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="tokenCredential"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            TokenCredential tokenCredential,
            IKeyVaultConfiguration configuration,
            ICacheConfiguration cacheConfiguration)
        {
            return AddAzureKeyVault(
                builder,
                tokenCredential,
                configuration,
                cacheConfiguration,
                configureOptions: null,
                name: null,
                mutateSecretName: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="tokenCredential"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            TokenCredential tokenCredential,
            IKeyVaultConfiguration configuration)
        {
            return AddAzureKeyVault(
                builder,
                tokenCredential,
                configuration,
                cacheConfiguration: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="name">The unique name to register this Azure Key Vault provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="tokenCredential"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            TokenCredential tokenCredential,
            IKeyVaultConfiguration configuration,
            ICacheConfiguration cacheConfiguration,
            Action<KeyVaultOptions> configureOptions,
            string name,
            Func<string, string> mutateSecretName)
        {
            return AddAzureKeyVault(
                builder,
                tokenCredential,
                configuration,
                cacheConfiguration,
                configureOptions,
                options =>
                {
                    options.Name = name;
                    options.MutateSecretName = mutateSecretName;
                });
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configuration">The configuration related to the Azure Key Vault instance to use.</param>
        /// <param name="cacheConfiguration">The configuration to control how the caching will be done, use the <see cref="CacheConfiguration.Default"/> for default caching.</param>
        /// <param name="configureOptions">The optional additional options to configure the Azure Key Vault secret source.</param>
        /// <param name="configureProviderOptions">The optional additional options to configure the secret provider registration in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="tokenCredential"/>, or <paramref name="configuration"/> is <c>null</c>.</exception>
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 as different Azure Key Vault authentication mechanism will be consolidated")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            TokenCredential tokenCredential,
            IKeyVaultConfiguration configuration,
            ICacheConfiguration cacheConfiguration,
            Action<KeyVaultOptions> configureOptions,
            Action<SecretProviderOptions> configureProviderOptions)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (tokenCredential is null)
            {
                throw new ArgumentNullException(nameof(tokenCredential));
            }

            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

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

                var cachedSecretProvider = new KeyVaultCachedSecretProvider(keyVaultSecretProvider, cacheConfiguration);
                return cachedSecretProvider;
            }, configureProviderOptions);
        }
    }
}
