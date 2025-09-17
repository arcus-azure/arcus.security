using System;

namespace Arcus.Security.Providers.AzureKeyVault.Configuration
{
    /// <summary>
    ///     Configuration for interaction with a Azure Key Vault instance
    /// </summary>
    [Obsolete("Will be removed in v3.0 as the vault URI can be passed directly to the registration")]
    public interface IKeyVaultConfiguration
    {
        /// <summary>
        ///     The Uri of the Azure Key Vault you want to connect to.
        /// </summary>
        /// <example>https://{vaultname}.vault.azure.net/</example>
        Uri VaultUri { get; }
    }
}