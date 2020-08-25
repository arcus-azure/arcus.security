using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;

namespace Arcus.Security.Tests.Unit.Core.Stubs
{
    /// <summary>
    /// <see cref="ICachedSecretProvider"/> implementation that provides an in-memory storage of secrets by name.
    /// </summary>
    public class InMemoryCachedSecretProvider : InMemorySecretProvider, ICachedSecretProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InMemoryCachedSecretProvider"/> class.
        /// </summary>
        /// <param name="secretValueByName">The sequence of combinations of secret names and values.</param>
        public InMemoryCachedSecretProvider(params (string name, string value)[] secretValueByName) : base(secretValueByName)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemoryCachedSecretProvider"/> class.
        /// </summary>
        /// <param name="secretValueByName">The sequence of combinations of secret names and values.</param>
        public InMemoryCachedSecretProvider(IDictionary<string, string> secretValueByName) : base(secretValueByName)
        {
        }

        /// <summary>
        /// Gets the cache-configuration for this instance.
        /// </summary>
        public ICacheConfiguration Configuration => null;

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="System.Threading.Tasks.Task{TResult}"/> that contains the secret key</returns>
        /// <exception cref="System.ArgumentException">The name must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> GetRawSecretAsync(string secretName, bool ignoreCache)
        {
            string secretValue = await base.GetRawSecretAsync(secretName);
            return secretValue;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="System.Threading.Tasks.Task{TResult}"/> that contains the secret key</returns>
        /// <exception cref="System.ArgumentException">The name must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName, bool ignoreCache)
        {
            Secret secret = await base.GetSecretAsync(secretName);
            return secret;
        }

        /// <summary>
        /// Removes the secret with the given <paramref name="secretName"/> from the cache;
        /// so the next time <see cref="CachedSecretProvider.GetSecretAsync(string)"/> is called, a new version of the secret will be added back to the cache.
        /// </summary>
        /// <param name="secretName">The name of the secret that should be removed from the cache.</param>
        public Task InvalidateSecretAsync(string secretName)
        {
            return Task.CompletedTask;
        }
    }
}
