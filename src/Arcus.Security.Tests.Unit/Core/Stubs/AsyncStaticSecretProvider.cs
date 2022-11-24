using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Core;

namespace Arcus.Security.Tests.Unit.Core.Stubs
{
    internal class AsyncStaticSecretProvider : ISecretProvider
    {
        private readonly string _secretValue;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsyncStaticSecretProvider" /> class.
        /// </summary>
        public AsyncStaticSecretProvider(string secretValue)
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
    }
}
