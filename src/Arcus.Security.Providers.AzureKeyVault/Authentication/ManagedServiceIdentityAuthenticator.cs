using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication
{
    /// <summary>
    ///     Azure Key Vault authentication by using Azure Managed Service Identity
    /// </summary>
    public class ManagedServiceIdentityAuthenticator : IKeyVaultAuthentication
    {
        /// <summary>
        /// Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="KeyVaultClient"/> client to use for interaction with the vault</returns>
        public Task<IKeyVaultClient> Authenticate()
        {
            var tokenProvider = new AzureServiceTokenProvider();
            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback);
            IKeyVaultClient keyVaultClient = new KeyVaultClient(authenticationCallback);

            return Task.FromResult(keyVaultClient);
        }
    }
}