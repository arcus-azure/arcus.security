using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;

namespace Arcus.Security.Providers.AzureKeyVault.Authentication
{
    /// <summary>
    ///     Azure Key Vault authentication by using Azure Managed Service Identity
    /// </summary>
#pragma warning disable 618
    public class ManagedServiceIdentityAuthenticator : IKeyVaultAuthentication, IKeyVaultAuthenticator
#pragma warning restore 618
    {
        private readonly string _connectionString;

        private readonly string _azureAdInstance;

        /// <summary>
        /// Initializes a new instance of the <see cref="ManagedServiceIdentityAuthenticator"/> class.
        /// </summary>
        /// <param name="connectionString">The connection string to use to authenticate.</param>
        /// <param name="azureAdInstance">The azure AD instance to use to authenticate, if applicable.</param>
        public ManagedServiceIdentityAuthenticator(string connectionString = null, string azureAdInstance = null)
        {
            _connectionString = connectionString;
            _azureAdInstance = azureAdInstance;
        }

        /// <summary>
        /// Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="IKeyVaultClient"/> client to use for interaction with the vault</returns>
        [Obsolete("Use the " + nameof(AuthenticateAsync) + " method instead ")]
        public Task<IKeyVaultClient> Authenticate()
        {
            IKeyVaultClient client = AuthenticateClient();
            return Task.FromResult(client);
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="KeyVaultClient" /> client to use for interaction with the vault</returns>
        [Obsolete("Use the " + nameof(AuthenticateAsync) + " method instead")]
        Task<KeyVaultClient> IKeyVaultAuthenticator.Authenticate()
        {
            KeyVaultClient client = AuthenticateClient();
            return Task.FromResult(client);
        }

        /// <summary>
        ///     Authenticates with Azure Key Vault
        /// </summary>
        /// <returns>A <see cref="IKeyVaultClient" /> client to use for interaction with the vault</returns>
        public Task<IKeyVaultClient> AuthenticateAsync()
        {
            IKeyVaultClient keyVaultClient = AuthenticateClient();
            return Task.FromResult(keyVaultClient);
        }

        private KeyVaultClient AuthenticateClient()
        {
            // Unfortunately the default azureAdInstance is hardcoded to a value rather than null, avoid having to hard code the value here too.
            var tokenProvider = _azureAdInstance == null ? new AzureServiceTokenProvider(_connectionString) : new AzureServiceTokenProvider(_connectionString, _azureAdInstance);

            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback);
            
            var keyVaultClient = new KeyVaultClient(authenticationCallback);

            return keyVaultClient;
        }
    }
}
