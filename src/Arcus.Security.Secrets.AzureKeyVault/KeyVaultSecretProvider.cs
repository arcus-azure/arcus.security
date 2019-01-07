using System.Net;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Factories;
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
        private readonly KeyVaultClientFactory _keyVaultClientFactory;
        private KeyVaultClient _keyVaultClient;
        
        /// <summary>
        /// Uri of the vault
        /// </summary>
        public string VaultUri { get; }

        /// <summary>
        /// Creates an Azure Key Vault Secret provider, connected to a specific Azure Key Vault
        /// </summary>
        /// <param name="keyVaultClientFactory">A <see cref="KeyVaultClientFactory"/> implementation that will be used to generate the Key VaultClient</param>
        /// <param name="keyVaultUri">The Uri of the Azure Key Vault you want to connect to.  <example>https://{vaultname}.vault.azure.net/</example></param>
        public KeyVaultSecretProvider(KeyVaultClientFactory keyVaultClientFactory, string keyVaultUri)
        {
            Guard.NotNullOrEmpty(keyVaultUri, nameof(keyVaultUri));
            Guard.NotNull(keyVaultClientFactory, nameof(keyVaultClientFactory));

            VaultUri = keyVaultUri;
            _keyVaultClientFactory = keyVaultClientFactory;
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
                SecretBundle secretBundle = await keyVaultClient.GetSecretAsync(VaultUri, secretName);
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
                _keyVaultClient = await _keyVaultClientFactory.CreateClient();
            }

            return _keyVaultClient;
        }
    }
}
