using System;
using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.Hosting;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Kubernetes;
using VaultSharp.V1.AuthMethods.UserPass;
using VaultSharp.V1.SecretsEngines;

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
        ///     See more information on HashiCorp: https://learn.hashicorp.com/tutorials/vault/getting-started-install.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets to.</param>
        /// <param name="vaultServerUriWithPort">The URI that points to the running HashiCorp Vault.</param>
        /// <param name="userName">The username of the UserPass authentication method.</param>
        /// <param name="password">The password of the UserPass authentication method.</param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <param name="secretEngineVersion">The client API version to use when interacting with the KeyValue secret engine.</param>
        /// <param name="mountPoint">The point where HashiCorp Vault KeyVault secret engine is mounted.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="secretPath"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="vaultServerUriWithPort"/> is blank or doesn't represent a valid URI,
        ///     or the <paramref name="userName"/> or <paramref name="password"/> is blank,
        ///     or the <paramref name="secretPath"/> is empty or contains <c>null</c> values,
        ///     or the <paramref name="secretEngineVersion"/> isn't within the bounds of the enumeration.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVaultWithUserPass(
            this SecretStoreBuilder builder,
            string vaultServerUriWithPort,
            string userName,
            string password,
            string secretPath,
            VaultKeyValueSecretEngineVersion secretEngineVersion = VaultKeyValueSecretEngineVersion.V2,
            string mountPoint = SecretsEngineDefaultPaths.KeyValueV2)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the HashiCorp Vault secret provider");
            Guard.NotNullOrWhitespace(vaultServerUriWithPort, nameof(vaultServerUriWithPort));
            Guard.NotNullOrWhitespace(userName, nameof(userName), "Requires a username for the UserPass authentication during connecting with the HashiCorp Vault");
            Guard.NotNullOrWhitespace(password, nameof(password), "Requires a password for the UserPass authentication during connecting with the HashiCorp Vault");
            Guard.NotNullOrWhitespace(secretPath, nameof(secretPath), "Requires a path where the HashiCorp Vault secrets are stored");
            Guard.For<ArgumentException>(() => !Uri.IsWellFormedUriString(vaultServerUriWithPort, UriKind.RelativeOrAbsolute), "Requires a HashiCorp Vault server URI with HTTP port");
            Guard.For<ArgumentException>(() => !Enum.IsDefined(typeof(VaultKeyValueSecretEngineVersion), secretEngineVersion), "Requires the client API version to be either V1 or V2");

            IAuthMethodInfo authenticationMethod = new UserPassAuthMethodInfo(userName, password);
            var settings = new VaultClientSettings(vaultServerUriWithPort, authenticationMethod);

            return AddHashiCorpVault(builder, settings, secretPath, secretEngineVersion, mountPoint);
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: https://learn.hashicorp.com/tutorials/vault/getting-started-install.
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
        /// <param name="secretEngineVersion">The client API version to use when interacting with the KeyValue secret engine.</param>
        /// <param name="mountPoint">The point where HashiCorp Vault KeyVault secret engine is mounted.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="vaultServerUriWithPort"/> is blank or doesn't represent a valid URI,
        ///     or the <paramref name="jsonWebToken"/> is blank,
        ///     or the <paramref name="secretPath"/> is blank,
        ///     or the <paramref name="secretEngineVersion"/> isn't within the bounds of the enumeration.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVaultWithKubernetes(
            this SecretStoreBuilder builder,
            string vaultServerUriWithPort,
            string roleName,
            string jsonWebToken,
            string secretPath,
            VaultKeyValueSecretEngineVersion secretEngineVersion = VaultKeyValueSecretEngineVersion.V2,
            string mountPoint = SecretsEngineDefaultPaths.KeyValueV2)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the HashiCorp Vault secret provider");
            Guard.NotNullOrWhitespace(vaultServerUriWithPort, nameof(vaultServerUriWithPort), "Requires a valid HashiCorp Vault URI with HTTP port to connect to the running HashiCorp Vault");
            Guard.NotNullOrWhitespace(jsonWebToken, nameof(jsonWebToken), "Requires a valid Json Web Token (JWT) during the Kubernetes authentication procedure");
            Guard.NotNullOrWhitespace(secretPath, nameof(secretPath), "Requires a path where the HashiCorp Vault secrets are stored");
            Guard.For<ArgumentException>(() => !Uri.IsWellFormedUriString(vaultServerUriWithPort, UriKind.RelativeOrAbsolute), "Requires a HashiCorp Vault server URI with HTTP port");
            Guard.For<ArgumentException>(() => !Enum.IsDefined(typeof(VaultKeyValueSecretEngineVersion), secretEngineVersion), "Requires the client API version to be either V1 or V2");

            IAuthMethodInfo authenticationMethod = new KubernetesAuthMethodInfo(roleName, jsonWebToken);
            var settings = new VaultClientSettings(vaultServerUriWithPort, authenticationMethod);

            return AddHashiCorpVault(builder, settings, secretPath, secretEngineVersion, mountPoint);
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: https://learn.hashicorp.com/tutorials/vault/getting-started-install.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets to.</param>
        /// <param name="settings"></param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <param name="secretEngineVersion">The client API version to use when interacting with the KeyValue secret engine.</param>
        /// <param name="mountPoint">The point where HashiCorp Vault KeyVault secret engine is mounted.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="builder"/>, <paramref name="settings"/> or <paramref name="secretPath"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="settings"/> doesn't have a valid Vault server URI or a missing authentication method,
        ///     or the <paramref name="secretPath"/> is empty or contains <c>null</c> values,
        ///     or the <paramref name="secretEngineVersion"/> isn't within the bounds of the enumeration
        ///     or the <paramref name="mountPoint"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVault(
            this SecretStoreBuilder builder,
            VaultClientSettings settings,
            string secretPath,
            VaultKeyValueSecretEngineVersion secretEngineVersion = VaultKeyValueSecretEngineVersion.V2,
            string mountPoint = SecretsEngineDefaultPaths.KeyValueV2)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the HashiCorp Vault secret provider");
            Guard.NotNull(settings, nameof(settings), "Requires HashiCorp Vault settings to correctly connect to the running HashiCorp Vault");
            Guard.NotNull(settings.VaultServerUriWithPort, nameof(settings.VaultServerUriWithPort), "Requires the HashiCorp Vault settings to have a valid URI with HTTP port");
            Guard.NotNull(settings.AuthMethodInfo, nameof(settings.AuthMethodInfo), "Requires the HashiCorp Vault settings to have an authentication method configured");
            Guard.NotNullOrWhitespace(secretPath, nameof(secretPath), "Requires a secret path to look for secret values");
            Guard.For<ArgumentException>(() => !Uri.IsWellFormedUriString(settings.VaultServerUriWithPort, UriKind.RelativeOrAbsolute), "Requires a HashiCorp Vault server URI with HTTP port");
            Guard.For<ArgumentException>(() => !Enum.IsDefined(typeof(VaultKeyValueSecretEngineVersion), secretEngineVersion), "Requires the client API version to be either V1 or V2");
            Guard.NotNullOrWhitespace(mountPoint, nameof(mountPoint), "Requires a point where the KeyVault secret engine is mounted");

            var provider = new HashiCorpSecretProvider(settings, secretEngineVersion, mountPoint, secretPath);
            return builder.AddProvider(provider);
        }
    }
}
