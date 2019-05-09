using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using GuardNet;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication
{
    /// <summary>
    /// Representation of an <see cref="IKeyVaultAuthentication"/> that will generate a <see cref="IKeyVaultClient"/> implementation using a service principle.
    /// </summary>
#pragma warning disable 618
    public class ServicePrincipalAuthenticator : IKeyVaultAuthentication, IKeyVaultAuthenticator
#pragma warning restore 618
    {
        private readonly string _clientId;
        private readonly string _clientKey;

        /// <summary>
        /// Initializes <see cref="ServicePrincipalAuthenticator"/> that will generate a KeyVaultClient, using a service principal
        /// </summary>
        /// <param name="clientId">The ClientId of the service principal, used to connect to Azure Key Vault</param>
        /// <param name="clientKey">The Secret ClientKey of the service principal, used to connect to Azure Key Vault</param>
        public ServicePrincipalAuthenticator(string clientId, string clientKey)
        {
            Guard.NotNullOrEmpty(clientId, nameof(clientId));
            Guard.NotNullOrEmpty(clientKey, nameof(clientKey));

            _clientId = clientId;
            _clientKey = clientKey;
        }
        
        /// <summary>
        /// Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="KeyVaultClient"/> client to use for interaction with the vault</returns>
        public Task<IKeyVaultClient> Authenticate()
        {
            IKeyVaultClient keyVaultClient = new KeyVaultClient(GetToken);
            return Task.FromResult(keyVaultClient);
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="KeyVaultClient" /> client to use for interaction with the vault</returns>
        Task<KeyVaultClient> IKeyVaultAuthenticator.Authenticate()
        {
            var keyVaultClient = new KeyVaultClient(GetToken);
            return Task.FromResult(keyVaultClient);
        }

        private async Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            var clientCred = new ClientCredential(_clientId, _clientKey);
            var result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
            {
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }

            return result.AccessToken;
        }
    }
}
