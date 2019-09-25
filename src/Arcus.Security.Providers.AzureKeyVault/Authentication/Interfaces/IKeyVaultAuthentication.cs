using Microsoft.Azure.KeyVault;
using System.Threading.Tasks;

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
        /// <returns>A <see cref="IKeyVaultClient" /> client to use for interaction with the vault</returns>
        Task<IKeyVaultClient> AuthenticateAsync();
    }
}