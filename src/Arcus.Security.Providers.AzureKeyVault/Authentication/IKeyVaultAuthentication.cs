using System;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication
{
    /// <summary>
    ///     Authentication provider for Azure Key Vault
    /// </summary>
    [Obsolete("Azure Key Vault authentication is moved to Azure Identity approach so this interface contract is not needed anymore")]
    public interface IKeyVaultAuthentication
    {
        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="IKeyVaultClient" /> client to use for interaction with the vault</returns>
        Task<IKeyVaultClient> AuthenticateAsync();
    }
}