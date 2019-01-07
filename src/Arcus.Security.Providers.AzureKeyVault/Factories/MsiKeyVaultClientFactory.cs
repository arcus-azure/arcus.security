using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;

namespace Arcus.Security.Providers.AzureKeyVault.Factories
{
    /// <summary>
    /// <see cref="KeyVaultClientFactory"/> implementation using Azure Managed Service Identity
    /// </summary>
    public class MsiKeyVaultClientFactory : KeyVaultClientFactory
    {
        /// <summary>
        /// Creates a <see cref="KeyVaultClient"/>, using the AzureServiceTokenProvider
        /// </summary>
        /// <returns>A generated KeyVaultClient</returns>
        public override Task<KeyVaultClient> CreateClient()
        {
            var tokenProvider = new AzureServiceTokenProvider();
            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback);
            var keyVaultClient = new KeyVaultClient(authenticationCallback);

            return Task.FromResult(keyVaultClient);
        }
    }
}
