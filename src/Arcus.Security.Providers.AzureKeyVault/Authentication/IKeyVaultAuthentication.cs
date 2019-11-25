using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication
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