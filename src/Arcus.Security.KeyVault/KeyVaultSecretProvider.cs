using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Core.Exceptions;
using Arcus.Security.Core.Interfaces;
using Arcus.Security.KeyVault.Factories;
using GuardNet;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Core;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Arcus.Security.KeyVault
{
    /// <summary>
    /// Secret key provider that connects to Azure Key Vault
    /// </summary>
    public class KeyVaultSecretProvider : ISecretProvider
    {
        private readonly string _keyVaultUri;
        private readonly KeyVaultClientFactory _keyVaultClientFactory;
        private KeyVaultClient _keyVaultClient;

        /// <summary>
        /// Creates an Azure KeyVault Secret provider, connected to a specific Azure Key Vault
        /// </summary>
        /// <param name="keyVaultClientFactory">A <see cref="KeyVaultClientFactory"/> implementation that will be used to generate the KeyVaultClient</param>
        /// <param name="keyVaultUri">The Uri of the Azure KeyVault you want to connect to.  <example>https://{vaultname}nebulus-iot.vault.azure.net/</example></param>
        public KeyVaultSecretProvider(KeyVaultClientFactory keyVaultClientFactory, string keyVaultUri)
        {
            Guard.NotNullOrEmpty(keyVaultUri, nameof(keyVaultUri));
            Guard.NotNull(keyVaultClientFactory, nameof(keyVaultClientFactory));
            _keyVaultUri = keyVaultUri;
            _keyVaultClientFactory = keyVaultClientFactory;
        }

        // Moving this implementation here, as KeyVaultClient cannot be mocked (https://github.com/Azure/azure-sdk-for-java/issues/1552)
        // Therefore, constructor will not try to create the client 
        private KeyVaultClient KeyVaultClient => 
            _keyVaultClient ?? (_keyVaultClient = _keyVaultClientFactory.CreateClient().Result);

        /// <summary>
        /// Gets the secret from KeyVault, using the right secret name
        /// </summary>
        /// <param name="name">The secret name</param>
        /// <returns>The value, stored in KeyVault</returns>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> Get(string name)
        {
            Guard.NotNullOrEmpty(name, nameof(name));
            try
            {
                SecretBundle secretBundle = await KeyVaultClient.GetSecretAsync(_keyVaultUri, name);
                return secretBundle?.Value;
            }
            catch (KeyVaultErrorException kvException)
            {
                if (kvException.Response.StatusCode == HttpStatusCode.NotFound)
                {
                    throw new SecretNotFoundException(name, kvException);
                }

                throw;
            }
        }
    }
}
