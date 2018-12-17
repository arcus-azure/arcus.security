using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Core.Interfaces;

namespace Arcus.Security.KeyVault
{
    public class KeyVaultSecretProvider : ISecretProvider
    {
        public async Task<string> Get(string name)
        {
            throw new NotImplementedException();
        }
    }
}
