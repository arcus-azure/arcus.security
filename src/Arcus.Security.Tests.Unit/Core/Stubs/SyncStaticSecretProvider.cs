using System.Threading.Tasks;
using Arcus.Security.Core;

namespace Arcus.Security.Tests.Unit.Core.Stubs
{
    internal class SyncStaticSecretProvider : ISyncSecretProvider
    {
        private readonly string _secretValue;

        /// <summary>
        /// Initializes a new instance of the <see cref="SyncStaticSecretProvider" /> class.
        /// </summary>
        public SyncStaticSecretProvider(string secretValue)
        {
            _secretValue = secretValue;
        }

        public Task<string> GetRawSecretAsync(string secretName)
        {
            return Task.FromResult(_secretValue);
        }

        public Task<Secret> GetSecretAsync(string secretName)
        {
            return Task.FromResult(new Secret(_secretValue));
        }

        public string GetRawSecret(string secretName)
        {
            return _secretValue;
        }

        public Secret GetSecret(string secretName)
        {
            return new Secret(_secretValue);
        }
    }
}