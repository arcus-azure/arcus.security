using System;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching.Configuration;
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
        private readonly ICacheConfiguration _cacheConfiguration;

        /// <summary>
        /// Creating a new CachedSecretProvider with all required information
        /// </summary>
        /// <param name="secretProvider">The internal <see cref="ISecretProvider"/> used to retrieve the actual Secret Value, when not cached</param>
        /// <param name="cacheConfiguration">The <see cref="ICacheConfiguration"/> which defines how the cache works</param>
        /// <param name="memoryCache">A <see cref="IMemoryCache"/> implementation that can cache data in memory.</param>
        /// <exception cref="ArgumentNullException">The secretProvider and memoryCache parameters must not be null</exception>
        public CachedSecretProvider(ISecretProvider secretProvider, ICacheConfiguration cacheConfiguration, IMemoryCache memoryCache)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider));
            Guard.NotNull(memoryCache, nameof(memoryCache));
            Guard.NotNull(cacheConfiguration, nameof(cacheConfiguration));

            _secretProvider = secretProvider;
            _cacheConfiguration = cacheConfiguration;
            
            MemoryCache = memoryCache;

            CacheEntry = new MemoryCacheEntryOptions()
                // Keep in cache for this time, reset time if accessed.
                .SetSlidingExpiration(Configuration.Duration);
        }

        /// <inheritdoc />
        /// <summary>
        /// Creating a new CachedSecretProvider with a standard generated MemoryCache
        /// </summary>
        public CachedSecretProvider(ISecretProvider secretProvider, ICacheConfiguration cacheConfiguration) :
            this(secretProvider, cacheConfiguration, new MemoryCache(new MemoryCacheOptions()))
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// Creating a new CachedSecretProvider with a standard generated MemoryCache and default TimeSpan of 5 minutes
        /// </summary>
        public CachedSecretProvider(ISecretProvider secretProvider) :
            this(secretProvider, new CacheConfiguration(), new MemoryCache(new MemoryCacheOptions()))
        {
        }

        /// <summary>
        /// Gets the in-memory cache where the cached secrets are stored.
        /// </summary>
        protected IMemoryCache MemoryCache { get; }

        /// <summary>
        /// Gets the options to configure the values set into the <see cref="MemoryCache"/>.
        /// </summary>
        protected MemoryCacheEntryOptions CacheEntry { get; }

        /// <summary>
        /// Gets the cache-configuration for this instance.
        /// </summary>
        public ICacheConfiguration Configuration => _cacheConfiguration;

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<string> GetRawSecretAsync(string secretName)
        {
            return GetRawSecretAsync(secretName, ignoreCache: false);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<Secret> GetSecretAsync(string secretName)
        {
            return GetSecretAsync(secretName, ignoreCache: false);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="Task{TResult}"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> GetRawSecretAsync(string secretName, bool ignoreCache)
        {
            Secret secret = await GetSecretAsync(secretName, ignoreCache);
            return secret?.Value;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="Task{TResult}"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName, bool ignoreCache)
        {
            if (ignoreCache == false && MemoryCache.TryGetValue(secretName, out Secret cachedSecret))
            {
                return cachedSecret;
            }

            Task<Secret> getSecret = _secretProvider.GetSecretAsync(secretName);
            Secret secret = getSecret == null ? null : await getSecret;

            MemoryCache.Set(secretName, secret, CacheEntry);
            return secret;
        }

        /// <summary>
        /// Removes the secret with the given <paramref name="secretName"/> from the cache;
        /// so the next time <see cref="GetSecretAsync(string)"/> is called, a new version of the secret will be added back to the cache.
        /// </summary>
        /// <param name="secretName">The name of the secret that should be removed from the cache.</param>
        public Task InvalidateSecretAsync(string secretName)
        {
            Guard.NotNullOrEmpty(secretName, nameof(secretName), "Cannot invalidate a cached secret with an empty name");

            MemoryCache.Remove(secretName);
            return Task.CompletedTask;
        }
    }
}
