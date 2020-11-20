using System;
using System.Net;
using Arcus.Security.Core;
using Arcus.Security.Providers.HashiCorp.Configuration;
using GuardNet;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Kubernetes;
using VaultSharp.V1.AuthMethods.UserPass;

namespace Arcus.Security.Providers.HashiCorp.Extensions
{
    /// <summary>
    /// Extensions on the <see cref="SecretStoreBuilder"/> to add the HashiCorp Vault as <see cref="ISecretProvider"/>.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: https://www.vaultproject.io/docs.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets to.</param>
        /// <param name="vaultServerUriWithPort">The URI that points to the running HashiCorp Vault.</param>
        /// <param name="username">The username of the UserPass authentication method.</param>
        /// <param name="password">The password of the UserPass authentication method.</param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <param name="configureOptions">The function to set the additional options to configure the HashiCorp Vault KeyValue.</param>
        /// <param name="configureSecretProviderOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="secretPath"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="vaultServerUriWithPort"/> is blank or doesn't represent a valid URI,
        ///     or the <paramref name="username"/> or <paramref name="password"/> is blank,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVaultWithUserPass(
            this SecretStoreBuilder builder,
            string vaultServerUriWithPort,
            string username,
            string password,
            string secretPath,
            Action<HashiCorpVaultUserPassOptions> configureOptions = null,
            Action<SecretProviderOptions> configureSecretProviderOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the HashiCorp Vault secret provider");
            Guard.NotNullOrWhitespace(vaultServerUriWithPort, nameof(vaultServerUriWithPort), "Requires a valid HashiCorp Vault URI with HTTP port to connect to the running HashiCorp Vault");
            Guard.NotNullOrWhitespace(username, nameof(username), "Requires a username for the UserPass authentication during connecting with the HashiCorp Vault");
            Guard.NotNullOrWhitespace(password, nameof(password), "Requires a password for the UserPass authentication during connecting with the HashiCorp Vault");
            Guard.NotNullOrWhitespace(secretPath, nameof(secretPath), "Requires a path where the HashiCorp Vault secrets are stored");
            Guard.For<ArgumentException>(() => !Uri.IsWellFormedUriString(vaultServerUriWithPort, UriKind.RelativeOrAbsolute), "Requires a HashiCorp Vault server URI with HTTP port");

            var options = new HashiCorpVaultUserPassOptions();
            configureOptions?.Invoke(options);

            IAuthMethodInfo authenticationMethod = new UserPassAuthMethodInfo(options.UserPassMountPoint, username, password);
            var settings = new VaultClientSettings(vaultServerUriWithPort, authenticationMethod);

            return AddHashiCorpVault(builder, settings, secretPath, options, configureSecretProviderOptions);
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: https://www.vaultproject.io/docs.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets to.</param>
        /// <param name="vaultServerUriWithPort">The URI that points to the running HashiCorp Vault.</param>
        /// <param name="roleName">
        ///     The name of the role in the Kubernetes authentication.
        ///     Role types have specific entities that can perform login operations against this endpoint.
        ///     Constraints specific to the role type must be set on the role. These are applied to the authenticated entities attempting to login.
        /// </param>
        /// <param name="jsonWebToken">The service account JWT used to access the TokenReview API to validate other JWTs during login.</param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <param name="configureOptions"></param>
        /// <param name="configureSecretProviderOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="vaultServerUriWithPort"/> is blank or doesn't represent a valid URI,
        ///     or the <paramref name="jsonWebToken"/> is blank,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVaultWithKubernetes(
            this SecretStoreBuilder builder,
            string vaultServerUriWithPort,
            string roleName,
            string jsonWebToken,
            string secretPath,
            Action<HashiCorpVaultKubernetesOptions> configureOptions = null,
            Action<SecretProviderOptions> configureSecretProviderOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the HashiCorp Vault secret provider");
            Guard.NotNullOrWhitespace(vaultServerUriWithPort, nameof(vaultServerUriWithPort), "Requires a valid HashiCorp Vault URI with HTTP port to connect to the running HashiCorp Vault");
            Guard.NotNullOrWhitespace(jsonWebToken, nameof(jsonWebToken), "Requires a valid Json Web Token (JWT) during the Kubernetes authentication procedure");
            Guard.NotNullOrWhitespace(secretPath, nameof(secretPath), "Requires a path where the HashiCorp Vault secrets are stored");
            Guard.For<ArgumentException>(() => !Uri.IsWellFormedUriString(vaultServerUriWithPort, UriKind.RelativeOrAbsolute), "Requires a HashiCorp Vault server URI with HTTP port");

            var options = new HashiCorpVaultKubernetesOptions();
            configureOptions?.Invoke(options);

            IAuthMethodInfo authenticationMethod = new KubernetesAuthMethodInfo(options.KubernetesMountPoint, roleName, jsonWebToken);
            var settings = new VaultClientSettings(vaultServerUriWithPort, authenticationMethod);

            return AddHashiCorpVault(builder, settings, secretPath, options, configureSecretProviderOptions);
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: https://www.vaultproject.io/docs.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets to.</param>
        /// <param name="settings"></param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <param name="configureOptions">The function to set the additional options to configure the HashiCorp Vault KeyValue.</param>
        /// <param name="configureSecretProviderOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="builder"/>, <paramref name="settings"/> or <paramref name="secretPath"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="settings"/> doesn't have a valid Vault server URI or a missing authentication method,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVault(
            this SecretStoreBuilder builder,
            VaultClientSettings settings,
            string secretPath,
            Action<HashiCorpVaultOptions> configureOptions = null,
            Action<SecretProviderOptions> configureSecretProviderOptions = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the HashiCorp Vault secret provider");
            Guard.NotNull(settings, nameof(settings), "Requires HashiCorp Vault settings to correctly connect to the running HashiCorp Vault");
            Guard.NotNullOrWhitespace(settings.VaultServerUriWithPort, nameof(settings.VaultServerUriWithPort), "Requires a non-blank HashiCorp Vault settings to have a valid URI with HTTP port");
            Guard.NotNull(settings.AuthMethodInfo, nameof(settings.AuthMethodInfo), "Requires the HashiCorp Vault settings to have an authentication method configured");
            Guard.NotNullOrWhitespace(secretPath, nameof(secretPath), "Requires a secret path to look for secret values");
            Guard.For<ArgumentException>(() => !Uri.IsWellFormedUriString(settings.VaultServerUriWithPort, UriKind.RelativeOrAbsolute), "Requires a HashiCorp Vault server URI with HTTP port");

            var options = new HashiCorpVaultOptions();
            configureOptions?.Invoke(options);

            return AddHashiCorpVault(builder, settings, secretPath, options, configureSecretProviderOptions);
        }

        private static SecretStoreBuilder AddHashiCorpVault(
            SecretStoreBuilder builder,
            VaultClientSettings settings,
            string secretPath,
            HashiCorpVaultOptions options,
            Action<SecretProviderOptions> configureSecretProviderOptions)
        {
            // Thrown when the HashiCorp Vault's authentication and/or authorization fails.
            builder.AddCriticalException<VaultApiException>(exception =>
            {
                return exception.HttpStatusCode == HttpStatusCode.BadRequest
                       || exception.HttpStatusCode == HttpStatusCode.Forbidden;
            });

            return builder.AddProvider(serviceProvider =>
            {
                var logger = serviceProvider.GetService<ILogger<HashiCorpSecretProvider>>();
                var provider = new HashiCorpSecretProvider(settings, secretPath, options, logger);
                
                return provider;
            }, configureSecretProviderOptions);
        }
    }
}
