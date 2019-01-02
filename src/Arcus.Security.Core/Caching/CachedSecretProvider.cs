using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Arcus.Security.Core.Exceptions;
using Arcus.Security.Core.Interfaces;
using GuardNet;
using Microsoft.Extensions.Caching.Memory;

namespace Arcus.Security.Core.Caching
{
    /// <inheritdoc cref="ISecretProvider"/>
    /// <summary>
    /// A Secret Provider that will cache secrets in memory, to improve performance
    /// </summary>
    public class CachedSecretProvider : ICachedSecretProvider
    {
        private readonly ISecretProvider _secretProvider;
        private readonly IMemoryCache _memoryCache;
        private readonly TimeSpan _cacheDuration;

        /// <summary>
        /// Creating a new CachedSecretProvider with all required information
        /// </summary>
        /// <param name="secretProvider">The internal <see cref="ISecretProvider"/> used to retrieve the actual Secret Value, when not cached</param>
        /// <param name="cacheDuration">The <see cref="TimeSpan"/> for which a retrieved value should be cached</param>
        /// <param name="memoryCache">A <see cref="IMemoryCache"/> implementation that can cache data in memory.</param>
        /// <exception cref="ArgumentNullException">The secretProvider and memoryCache parameters must not be null</exception>
        public CachedSecretProvider(ISecretProvider secretProvider, TimeSpan cacheDuration, IMemoryCache memoryCache)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider));
            Guard.NotNull(memoryCache, nameof(memoryCache));

            _secretProvider = secretProvider;
            _memoryCache = memoryCache;
            _cacheDuration = cacheDuration;
        }

        /// <inheritdoc />
        /// <summary>
        /// Creating a new CachedSecretProvider with a standard generated MemoryCache
        /// </summary>
        public CachedSecretProvider(ISecretProvider secretProvider, TimeSpan cacheDuration) :
            this(secretProvider, cacheDuration, new MemoryCache(new MemoryCacheOptions()))
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// Creating a new CachedSecretProvider with a standard generated MemoryCache and default TimeSpan of 5 minutes
        /// </summary>
        public CachedSecretProvider(ISecretProvider secretProvider) :
            this(secretProvider, TimeSpan.FromMinutes(5), new MemoryCache(new MemoryCacheOptions()))
        {
        }

        /// <summary>
        /// Retrieves the secret value from the cache (when available) or from the internal ISecretProvider
        /// </summary>
        /// <param name="name">The name of the secret value to be retrieved</param>
        /// <returns>The secret value</returns>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> Get(string name)
        {
            return await Get(name, false);
        }

        /// <summary>
        /// Retrieves the secret value from the cache (when available) or from the internal ISecretProvider
        /// </summary>
        /// <param name="name">The name of the secret value to be retrieved</param>
        /// <param name="skipCache">Indicates to skip the cache and force an update of the secret value</param>
        /// <returns>The secret value</returns>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> Get(string name, bool skipCache)
        {
            string secretValue;
            // Look for cache key.
            if (!_memoryCache.TryGetValue(name, out secretValue))
            {
                // Key not in cache, so get data.
                secretValue = await _secretProvider.Get(name);

                // Set cache options.
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    // Keep in cache for this time, reset time if accessed.
                    .SetSlidingExpiration(_cacheDuration);

                // Save data in cache.
                _memoryCache.Set(name, secretValue, cacheEntryOptions);
            }

            return secretValue;
        }
    }
}
