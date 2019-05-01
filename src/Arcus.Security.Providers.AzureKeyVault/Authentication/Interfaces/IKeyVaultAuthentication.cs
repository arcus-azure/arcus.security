using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces 
{
    /// <summary>
    ///     Authentication provider for Azure Key Vault
    /// </summary>
    public interface IKeyVaultAuthentication
    {
        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="KeyVaultClient" /> client to use for interaction with the vault</returns>
        Task<IKeyVaultClient> Authenticate();
    }
}