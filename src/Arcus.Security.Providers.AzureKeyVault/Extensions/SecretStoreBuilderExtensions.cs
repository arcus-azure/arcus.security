using System;
using System.Security.Cryptography.X509Certificates;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching.Configuration;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
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
        /// Adds an Azure Key Vault as a secret provider to the secret store.
        /// </summary>
        /// <param name="builder">The secret store builder to add the Azure Key Vault secrets to.</param>
        /// <param name="vaultUri">
        ///     <para>A URI to the vault on which the client operates. Appears as "DNS Name" in the Azure portal.</para>
        ///     <para>If you have a secret URI, use <see cref="KeyVaultSecretIdentifier" /> to parse the <see cref="KeyVaultSecretIdentifier.VaultUri" /> and other information.</para>
        ///     <para>You should validate that this URI references a valid Key Vault resource. See <see href="https://aka.ms/azsdk/blog/vault-uri" /> for details.</para>
        /// </param>
        /// <param name="credential">A <see cref="TokenCredential" /> used to authenticate requests to the vault.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="credential"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="vaultUri"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(this SecretStoreBuilder builder, string vaultUri, TokenCredential credential)
        {
            return AddAzureKeyVault(builder, vaultUri, credential, configureOptions: null);
        }

        /// <summary>
        /// Adds an Azure Key Vault as a secret provider to the secret store.
        /// </summary>
        /// <param name="builder">The secret store builder to add the Azure Key Vault secrets to.</param>
        /// <param name="vaultUri">
        ///     <para>A URI to the vault on which the client operates. Appears as "DNS Name" in the Azure portal.</para>
        ///     <para>If you have a secret URI, use <see cref="KeyVaultSecretIdentifier" /> to parse the <see cref="KeyVaultSecretIdentifier.VaultUri" /> and other information.</para>
        ///     <para>You should validate that this URI references a valid Key Vault resource. See <see href="https://aka.ms/azsdk/blog/vault-uri" /> for details.</para>
        /// </param>
        /// <param name="configureOptions">The optional function to manipulate the registration of the secret provider.</param>
        /// <param name="credential">A <see cref="TokenCredential" /> used to authenticate requests to the vault.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="credential"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="vaultUri"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            string vaultUri,
            TokenCredential credential,
            Action<KeyVaultSecretProviderOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentException.ThrowIfNullOrWhiteSpace(vaultUri);
            ArgumentNullException.ThrowIfNull(credential);

            return AddAzureKeyVault(builder, _ => new SecretClient(new Uri(vaultUri), credential), configureOptions);
        }


        /// <summary>
        /// Adds Azure Key Vault as a provider to the secret store.
        /// </summary>
        /// <param name="builder">The secret store builder to add the Azure Key Vault secrets to.</param>
        /// <param name="implementationFactory">The function to create the client to interact with Azure Key Vault.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="builder"/> or <paramref name="implementationFactory"/> is <c>null</c>.
        /// </exception>
        public static SecretStoreBuilder AddAzureKeyVault(this SecretStoreBuilder builder, Func<IServiceProvider, SecretClient> implementationFactory)
        {
            return AddAzureKeyVault(builder, implementationFactory, configureOptions: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a provider to the secret store.
        /// </summary>
        /// <param name="builder">The secret store builder to add the Azure Key Vault secrets to.</param>
        /// <param name="implementationFactory">The function to create the client to interact with Azure Key Vault.</param>
        /// <param name="configureOptions">The optional function to manipulate the registration of the secret provider.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="builder"/> or <paramref name="implementationFactory"/> is <c>null</c>.
        /// </exception>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            Func<IServiceProvider, SecretClient> implementationFactory,
            Action<KeyVaultSecretProviderOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(implementationFactory);

#pragma warning disable CS0618 // Type or member is obsolete
            AddCriticalExceptions(builder);
#pragma warning restore CS0618 // Type or member is obsolete

            return builder.AddProvider((serviceProvider, context, options) =>
            {
                SecretClient client = implementationFactory(serviceProvider);
                var logger = serviceProvider.GetService<ILogger<KeyVaultSecretProvider>>();

                return new KeyVaultSecretProvider(client, context, options, logger);

            }, configureOptions);
        }

        [Obsolete("Will be removed in v3.0")]
        private static void AddCriticalExceptions(SecretStoreBuilder builder)
        {
            // Thrown during failure with Key Vault authorization.
            builder.AddCriticalException<RequestFailedException>(exception =>
            {
                return exception.Status == 403 || exception.Status == 401 || exception.Status == 400;
            });

            builder.AddCriticalException<CredentialUnavailableException>();
            builder.AddCriticalException<AuthenticationFailedException>();
        }
    }

    /// <summary>
    /// Extensions on the <see cref="SecretStoreBuilder"/> to provide easy addition the Azure Key Vault secrets in the secret store.
    /// </summary>
    public static class DeprecatedSecretStoreBuilderExtensions
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
        [Obsolete("Will be removed in v3.0 in favor of simpler overloads that does not take in caching or telemetry options")]
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
