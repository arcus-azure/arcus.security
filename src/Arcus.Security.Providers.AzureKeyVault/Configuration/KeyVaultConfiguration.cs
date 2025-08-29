using System;

namespace Arcus.Security.Providers.AzureKeyVault.Configuration
{
    /// <summary>
    /// Default implementation of the collected configuration values required to interact with Azure Key Vault.
    /// </summary>
    [Obsolete("Will be removed in v3.0 as the vault URI can be passed directly to the registration")]
    public class KeyVaultConfiguration : IKeyVaultConfiguration
    {
        /// <summary>
        ///     The Uri of the Azure Key Vault you want to connect to.
        /// </summary>
        /// <example>https://{vaultname}.vault.azure.net/</example>
        public Uri VaultUri { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultConfiguration"/> class.
        /// </summary>
        /// <param name="vaultUri">The URI of the Azure Key Vault you want to connect to.</param>
        /// <exception cref="ArgumentNullException">Thrown when no <paramref name="vaultUri"/> was specified.</exception>
        /// <exception cref="UriFormatException">Thrown when the <paramref name="vaultUri"/> is not using https.</exception>
        public KeyVaultConfiguration(Uri vaultUri)
        {
            VaultUri = vaultUri ?? throw new ArgumentNullException(nameof(vaultUri));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultConfiguration"/> class.
        /// </summary>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="rawVaultUri"/> is not using https.</exception>
        public KeyVaultConfiguration(string rawVaultUri)
        {
            if (string.IsNullOrWhiteSpace(rawVaultUri))
            {
                throw new ArgumentException("Requires a non-blank Azure Key vault URI", nameof(rawVaultUri));
            }

            VaultUri = new Uri(rawVaultUri);
        }
    }
}