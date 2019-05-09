using System;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces
{
    /// <summary>
    ///     Authentication provider for Azure Key Vault
    /// </summary>
    [Obsolete(
        "Use the "
        + nameof(IKeyVaultAuthentication)
        + " instead to return an "
        + nameof(IKeyVaultClient)
        + " implementation instead of a concrete "
        + nameof(KeyVaultClient))]
    public interface IKeyVaultAuthenticator
    {
        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="KeyVaultClient" /> client to use for interaction with the vault</returns>
        Task<KeyVaultClient> Authenticate();
    }
}