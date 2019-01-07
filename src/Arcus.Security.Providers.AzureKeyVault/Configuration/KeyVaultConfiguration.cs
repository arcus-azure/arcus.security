using System;
using Arcus.Security.Providers.AzureKeyVault.Configuration.Interfaces;
using GuardNet;

namespace Arcus.Security.Providers.AzureKeyVault.Configuration
{
    public class KeyVaultConfiguration : IKeyVaultConfiguration
    {
        /// <summary>
        ///     The Uri of the Azure Key Vault you want to connect to.
        /// </summary>
        /// <example>https://{vaultname}.vault.azure.net/</example>
        public Uri VaultUri { get; }

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="vaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <exception cref="UriFormatException">Exception thrown when the vault is not using https</exception>
        /// <exception cref="ArgumentNullException">No vault uri was specified</exception>
        public KeyVaultConfiguration(Uri vaultUri)
        {
            Guard.NotNull(vaultUri, nameof(vaultUri));
            Guard.For<UriFormatException>(() => vaultUri.Scheme != Uri.UriSchemeHttps);

            VaultUri = vaultUri;
        }

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="rawVaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <exception cref="ArgumentNullException">Exception thrown when the vault is not using https</exception>
        public KeyVaultConfiguration(string rawVaultUri) : this(new Uri(rawVaultUri))
        {
        }
    }
}