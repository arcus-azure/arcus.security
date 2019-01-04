using System;
using System.Threading.Tasks;
using Arcus.Security.KeyVault.Factories;
using Microsoft.Azure.KeyVault;

namespace Arcus.Security.Tests.Unit.KeyVault.Stubs
{
    internal class KeyVaultClientFactoryStub : KeyVaultClientFactory
    {
        public override Task<KeyVaultClient> CreateClient()
        {
            throw new NotImplementedException();
        }
    }
}