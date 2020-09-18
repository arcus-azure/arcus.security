using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core;
using GuardNet;
using VaultSharp;
using VaultSharp.V1.Commons;

namespace Arcus.Security.Providers.HashiCorp
{
    /// <summary>
    /// <para>
    ///     Represents an <see cref="ISecretProvider"/> that interacts with a HashiCorp Vault KeyVault engine to retrieve secrets.
    /// </para>
    /// <para>
    ///     See more information on HashiCorp Vault: https://www.vaultproject.io/docs.
    /// </para>
    /// </summary>
    public class HashiCorpSecretProvider : ISecretProvider
    {
        private readonly VaultKeyValueSecretEngineVersion _secretEngineVersion;
        private readonly string _mountPoint;
        private readonly string _secretPath;
        private readonly IVaultClient _vaultClient;

        /// <summary>
        /// Initializes a new instance of the <see cref="HashiCorpSecretProvider"/> class.
        /// </summary>
        /// <param name="settings">The configuration and authentication settings to successfully connect to the HashiCorp Vault instance.</param>
        /// <param name="secretEngineVersion">The client API version of the KeyValue secret engine to use when retrieving HashiCorp secrets.</param>
        /// <param name="mountPoint">The point where HashiCorp Vault KeyValue secret engine is mounted.</param>
        /// <param name="secretPath">The HashiCorp secret path available in the KeyValue engine where this secret provider should look for secrets.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="settings"/>,
        ///     or <paramref name="secretPath"/> is <c>null</c>
        ///     or the <paramref name="settings"/> doesn't contain a authentication method.</exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="secretEngineVersion"/> is not within the bounds of the enumeration,
        ///     or the <paramref name="settings"/> doesn't contain a valid Vault URI.
        /// </exception>
        public HashiCorpSecretProvider(VaultClientSettings settings, VaultKeyValueSecretEngineVersion secretEngineVersion, string mountPoint, string secretPath)
        {
            Guard.NotNull(settings, nameof(settings), "Requires HashiCorp settings to successfully connect to the Vault");
            Guard.NotNull(settings.AuthMethodInfo, nameof(settings.AuthMethodInfo), "Requires a authentication method to connect to the HashiCorp Vault");
            Guard.NotNullOrWhitespace(mountPoint, nameof(mountPoint), "Requires a point where the HashiCorp Vault KeyValue secret engine is mounted");
            Guard.NotNullOrWhitespace(secretPath, nameof(secretPath), "Requires a path where the HashiCorp Vault KeyValue secret engine should look for secrets");
            Guard.For<ArgumentException>(() => !Uri.IsWellFormedUriString(settings.VaultServerUriWithPort, UriKind.RelativeOrAbsolute), "Requires a HashiCorp Vault server URI with HTTP port");
            Guard.For<ArgumentException>(() => !Enum.IsDefined(typeof(VaultKeyValueSecretEngineVersion), secretEngineVersion), "Requires the client API version to be either V1 or V2");

            _secretEngineVersion = secretEngineVersion;
            _mountPoint = mountPoint;
            _secretPath = secretPath;
            _vaultClient = new VaultClient(settings);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), 
                $"Requires a non-blank secret name to look up the secret in the HashiCorp Vault {_secretEngineVersion} KeyValue secret engine");

            Secret secret = await GetSecretAsync(secretName);
            return secret?.Value;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName),
                $"Requires a non-blank secret name to look up the secret in the HashiCorp Vault {_secretEngineVersion} KeyValue secret engine");

            SecretData result = await ReadSecretDataAsync(_secretPath);

            if (result.Data.TryGetValue(secretName, out object value) && value != null)
            {
                var version = result.Metadata?.Version.ToString();
                return new Secret(value.ToString(), version);
            }

            return null;
        }

        private async Task<SecretData> ReadSecretDataAsync(string secretPath)
        {
            switch (_secretEngineVersion)
            {
                case VaultKeyValueSecretEngineVersion.V1:
                    Secret<Dictionary<string, object>> secretV1 = 
                        await _vaultClient.V1.Secrets.KeyValue.V1.ReadSecretAsync(secretPath, mountPoint: _mountPoint);
                    return new SecretData { Data = secretV1.Data };
                
                case VaultKeyValueSecretEngineVersion.V2:
                    Secret<SecretData> secretV2 = 
                        await _vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(secretPath, mountPoint: _mountPoint);
                    return secretV2.Data;
                
                default:
                    throw new ArgumentOutOfRangeException(nameof(_secretEngineVersion), _secretEngineVersion, "Unknown HashiCorp Vault KeyValue secret engine version");
            }
        }
    }
}
