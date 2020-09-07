﻿using System;
using System.Text.RegularExpressions;
using GuardNet;

namespace Arcus.Security.Providers.AzureKeyVault.Configuration
{
    /// <summary>
    /// Default implementation of the collected configuration values required to interact with Azure Key Vault.
    /// </summary>
    public class KeyVaultConfiguration : IKeyVaultConfiguration
    {
        private const string VaultUriPattern = "^https:\\/\\/[0-9a-zA-Z\\-]{3,24}\\.vault.azure.net(\\/)?$";

        private readonly Regex _vaultUriRegex = new Regex(VaultUriPattern, RegexOptions.Compiled);

        /// <summary>
        ///     The Uri of the Azure Key Vault you want to connect to.
        /// </summary>
        /// <example>https://{vaultname}.vault.azure.net/</example>
        public Uri VaultUri { get; }

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="vaultUri">The Uri of the Azure Key Vault you want to connect to.</param>
        /// <exception cref="ArgumentNullException">No <paramref name="vaultUri"/> was specified</exception>
        /// <exception cref="UriFormatException">Exception thrown when the vault is not using https</exception>
        public KeyVaultConfiguration(Uri vaultUri)
        {
            Guard.NotNull(vaultUri, nameof(vaultUri));
            Guard.For<UriFormatException>(
                () => vaultUri.Scheme != Uri.UriSchemeHttps,
                "Requires the vault URI to have a 'https' scheme");
            Guard.For<UriFormatException>(
                () => !_vaultUriRegex.IsMatch(vaultUri.ToString()),
                "Requires the Azure Key Vault host to be in the right format, see https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning");

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