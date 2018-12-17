using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
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
        private readonly KeyVaultClient _keyVaultClient;

        public KeyVaultSecretProvider(KeyVaultClientFactory keyVaultClientFactory, string keyVaultUri)
        {
            Guard.NotNullOrEmpty(keyVaultUri, nameof(keyVaultUri));
            Guard.NotNull(keyVaultClientFactory, nameof(keyVaultClientFactory));
            _keyVaultUri = keyVaultUri;
            _keyVaultClient = keyVaultClientFactory.CreateClient().Result;
        }

        public async Task<string> Get(string name)
        {
            Guard.NotNullOrEmpty(name, nameof(name));
            SecretBundle secretBundle = await _keyVaultClient.GetSecretAsync(_keyVaultUri, name);
            return secretBundle?.Value;
        }
    }
}
