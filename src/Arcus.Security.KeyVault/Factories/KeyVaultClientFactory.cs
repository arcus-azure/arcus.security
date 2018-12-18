using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;

namespace Arcus.Security.KeyVault.Factories
{
    /// <summary>
    /// Abstract class to create <see cref="KeyVaultClient"/> object
    /// </summary>
    public abstract class KeyVaultClientFactory
    {
        /// <summary>
        /// Method to implement the creation of your own KeyVaultClient
        /// </summary>
        /// <returns>An initialized KeyVaultClient</returns>
        public abstract Task<KeyVaultClient> CreateClient();
    }
}
