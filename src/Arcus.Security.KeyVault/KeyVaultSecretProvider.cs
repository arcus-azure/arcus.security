using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Core;

namespace Arcus.Security.KeyVault
{
    public class KeyVaultSecretProvider : ISecretProvider
    {
        public async Task<string> GetAsync(string name)
        {
            throw new NotImplementedException();
        }
    }
}
