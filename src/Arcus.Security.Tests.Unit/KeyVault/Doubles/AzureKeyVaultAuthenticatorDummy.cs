using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault.Authentication.Interfaces;
using Microsoft.Azure.KeyVault;

namespace Arcus.Security.Tests.Unit.KeyVault.Doubles
{
    internal class AzureKeyVaultAuthenticatorDummy : IKeyVaultAuthentication
    {
        public Task<IKeyVaultClient> Authenticate()
        {
            throw new NotImplementedException();
        }
    }
}