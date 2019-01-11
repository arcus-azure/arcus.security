using System;

namespace Arcus.Security.Providers.AzureKeyVault.Configuration.Interfaces
{
    /// <summary>
    ///     Configuration for interaction with a Azure Key Vault instance
    /// </summary>
    public interface IKeyVaultConfiguration
    {
        /// <summary>
        ///     The Uri of the Azure Key Vault you want to connect to.
        /// </summary>
        /// <example>https://{vaultname}.vault.azure.net/</example>
        Uri VaultUri { get; }
    }
}