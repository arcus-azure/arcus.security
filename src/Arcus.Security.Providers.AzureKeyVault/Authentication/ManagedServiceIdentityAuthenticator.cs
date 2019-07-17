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

        private static KeyVaultClient AuthenticateClient()
        {
            var tokenProvider = new AzureServiceTokenProvider();
            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback);
            
            var keyVaultClient = new KeyVaultClient(authenticationCallback);
            return keyVaultClient;
        }
    }
}
