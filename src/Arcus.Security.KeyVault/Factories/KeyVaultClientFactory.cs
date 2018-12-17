using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;

namespace Arcus.Security.KeyVault.Factories
{
    public abstract class KeyVaultClientFactory
    {
        public abstract Task<KeyVaultClient> CreateClient();
    }
}
