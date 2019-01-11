using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using Microsoft.Azure.KeyVault;

namespace Arcus.Security.Tests.Unit.KeyVault.Dummies
{
    internal class AzureKeyVaultAuthenticatorDummy : IKeyVaultAuthenticator
    {
        public Task<KeyVaultClient> Authenticate()
        {
            throw new NotImplementedException();
        }
    }
}