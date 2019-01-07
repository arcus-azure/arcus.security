using System;

namespace Arcus.Security.Providers.AzureKeyVault.Configuration.Interfaces
{
    public interface IKeyVaultConfiguration
    {
        /// <summary>
        ///     The Uri of the Azure Key Vault you want to connect to.
        /// </summary>
        /// <example>https://{vaultname}.vault.azure.net/</example>
        Uri VaultUri { get; }
    }
}