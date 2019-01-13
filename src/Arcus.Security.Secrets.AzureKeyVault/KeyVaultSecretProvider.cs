using System;
using System.Net;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using Arcus.Security.Providers.AzureKeyVault.Configuration.Interfaces;
using Arcus.Security.Secrets.Core.Exceptions;
using Arcus.Security.Secrets.Core.Interfaces;
using GuardNet;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;

namespace Arcus.Security.Secrets.AzureKeyVault
{
    /// <summary>
    /// Secret key provider that connects to Azure Key Vault
    /// </summary>
    public class KeyVaultSecretProvider : ISecretProvider
    {
        private readonly IKeyVaultAuthenticator _authenticator;
        private readonly IKeyVaultConfiguration _vaultConfiguration;
        private KeyVaultClient _keyVaultClient;
        
        /// <summary>
        /// Uri of the vault
        /// </summary>
        public string VaultUri { get; }

        /// <summary>
        /// Creates an Azure Key Vault Secret provider, connected to a specific Azure Key Vault
        /// </summary>
        /// <param name="authenticator">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        public KeyVaultSecretProvider(IKeyVaultAuthenticator authenticator, IKeyVaultConfiguration vaultConfiguration)
        {
            Guard.NotNull(vaultConfiguration, nameof(vaultConfiguration));
            Guard.NotNull(authenticator, nameof(authenticator));

            VaultUri = $"{vaultConfiguration.VaultUri.Scheme}://{vaultConfiguration.VaultUri.Host}";

            _vaultConfiguration = vaultConfiguration;
            _authenticator = authenticator;
        }

        /// <summary>
        /// Gets the secret from Key Vault, using the right secret name
        /// </summary>
        /// <param name="secretName">The secret name</param>
        /// <returns>The value, stored in Key Vault</returns>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> Get(string secretName)
        {
            Guard.NotNullOrEmpty(secretName, nameof(secretName));
            try
            {
                var keyVaultClient = await GetClientAsync();
                SecretBundle secretBundle = 
                    await Policy.Handle<KeyVaultErrorException>(ex => ex.Response.StatusCode == HttpStatusCode.TooManyRequests)
                                .WaitAndRetryAsync(5, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt - 1)))
                                .ExecuteAsync(() => keyVaultClient.GetSecretAsync(VaultUri, secretName));
                
                return secretBundle?.Value;
            }
            catch (KeyVaultErrorException keyVaultErrorException)
            {
                if (keyVaultErrorException.Response.StatusCode == HttpStatusCode.NotFound)
                {
                    throw new SecretNotFoundException(secretName, keyVaultErrorException);
                }

                throw;
            }
        }

        private async Task<KeyVaultClient> GetClientAsync()
        {
            if (_keyVaultClient == null)
            {
                _keyVaultClient = await _authenticator.Authenticate();
            }

            return _keyVaultClient;
        }
    }
}
