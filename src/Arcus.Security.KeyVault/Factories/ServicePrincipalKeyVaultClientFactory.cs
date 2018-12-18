using System;
using System.Threading.Tasks;
using GuardNet;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Arcus.Security.KeyVault.Factories
{
    /// <summary>
    /// <see cref="KeyVaultClientFactory"/> implementation using a service principle
    /// </summary>        
    public class ServicePrincipalKeyVaultClientFactory : KeyVaultClientFactory
    {
        private readonly string _clientId;
        private readonly string _clientKey;

        /// <summary>
        /// Initializes <see cref="ServicePrincipalKeyVaultClientFactory"/> that will generate a KeyVaultClient, using a service principal
        /// </summary>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        public ServicePrincipalKeyVaultClientFactory(string clientId, string clientKey)
        {
            Guard.NotNullOrEmpty(clientId, nameof(clientId));
            Guard.NotNullOrEmpty(clientKey, nameof(clientKey));

            _clientId = clientId;
            _clientKey = clientKey;
        }

        /// <summary>
        /// Creates a <see cref="KeyVaultClient"/>, using the AzureServiceTokenProvider
        /// </summary>
        /// <returns>A generated KeyVaultClient</returns>
        public override Task<KeyVaultClient> CreateClient()
        {
            var keyVaultClient = new KeyVaultClient(GetToken);
            return Task.FromResult(keyVaultClient);
        }

        private async Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(_clientId, _clientKey);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
            {
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }

            return result.AccessToken;
        }
    }
}
