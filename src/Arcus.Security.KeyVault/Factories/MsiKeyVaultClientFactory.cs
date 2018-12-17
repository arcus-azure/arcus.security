using System;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;

namespace Arcus.Security.KeyVault.Factories
{
    public class MsiKeyVaultClientFactory : KeyVaultClientFactory
    {
        public override Task<KeyVaultClient> CreateClient()
        {
            var tokenProvider = new AzureServiceTokenProvider();
            return Task.FromResult(new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback)));
        }
    }
}
