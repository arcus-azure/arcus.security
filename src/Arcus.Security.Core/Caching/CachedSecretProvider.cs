using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching.Configuration;
using GuardNet;
using Microsoft.Extensions.Caching.Memory;

namespace Arcus.Security.Core.Caching
{
    /// <inheritdoc cref="ISecretProvider"/>
    /// <summary>
    /// A <see cref="ISecretProvider"/> that will cache secrets in memory, to improve performance.
    /// </summary>
    public class CachedSecretProvider : ICachedSecretProvider, IVersionedSecretProvider
    {
        private readonly ISecretProvider _secretProvider;
        private readonly ICacheConfiguration _cacheConfiguration;

        /// <summary>
        /// Creating a new <see cref="CachedSecretProvider"/> with all required information.
        /// </summary>
        /// <param name="secretProvider">The internal <see cref="ISecretProvider"/> used to retrieve the actual Secret Value, when not cached</param>
        /// <param name="cacheConfiguration">The <see cref="ICacheConfiguration"/> which defines how the cache works</param>
        /// <param name="memoryCache">A <see cref="IMemoryCache"/> implementation that can cache data in memory.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="secretProvider"/>, <paramref name="memoryCache"/>, or <paramref name="cacheConfiguration"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <see cref="ICacheConfiguration.Duration"/> is not a positive time duration.</exception>
        public CachedSecretProvider(ISecretProvider secretProvider, ICacheConfiguration cacheConfiguration, IMemoryCache memoryCache)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires a secret provider instance to include caching while retrieving secrets");
            Guard.NotNull(memoryCache, nameof(memoryCache), "Requires a memory caching implementation to include caching while retrieving secrets");
            Guard.NotNull(cacheConfiguration, nameof(cacheConfiguration), "Requires a configuration instance to influence the caching during the retrieval of secrets");
            Guard.NotLessThan(cacheConfiguration.Duration, TimeSpan.Zero, nameof(cacheConfiguration), 
                "Requires a positive time duration in the cache configuration in which the caching should take place");
            
            _secretProvider = secretProvider;
            _cacheConfiguration = cacheConfiguration;
            
            MemoryCache = memoryCache;

            CacheEntry = new MemoryCacheEntryOptions()
                // Keep in cache for this time, reset time if accessed.
                .SetSlidingExpiration(Configuration.Duration);
        }

        /// <inheritdoc />
        /// <summary>
        /// Creating a new <see cref="CachedSecretProvider"/> with a standard generated <see cref="IMemoryCache"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="secretProvider"/> or <paramref name="cacheConfiguration"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <see cref="ICacheConfiguration.Duration"/> is not a positive time duration.</exception>
        public CachedSecretProvider(ISecretProvider secretProvider, ICacheConfiguration cacheConfiguration) :
            this(secretProvider, cacheConfiguration, new MemoryCache(new MemoryCacheOptions()))
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// Creating a new <see cref="CachedSecretProvider"/> with a standard generated <see cref="IMemoryCache"/> and default <see cref="TimeSpan"/> of 5 minutes.
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public CachedSecretProvider(ISecretProvider secretProvider) :
            this(secretProvider, CacheConfiguration.Default, new MemoryCache(new MemoryCacheOptions()))
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");
            
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");
            
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");
            
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");
            
            if (ignoreCache == false && MemoryCache.TryGetValue(secretName, out Secret[] cachedSecret))
            {
                return cachedSecret.First();
            }

            Task<Secret> getSecret = _secretProvider.GetSecretAsync(secretName);
            Secret secret = getSecret == null ? null : await getSecret;

            MemoryCache.Set(secretName, new[] { secret }, CacheEntry);
            return secret;
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret value, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        public async Task<IEnumerable<string>> GetRawSecretsAsync(string secretName, int amountOfVersions)
        {
            IEnumerable<Secret> secrets = await GetSecretsAsync(secretName, amountOfVersions);
            return secrets?.Select(secret => secret?.Value).ToArray();
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        public async Task<IEnumerable<Secret>> GetSecretsAsync(string secretName, int amountOfVersions)
        {
            if (_secretProvider is IVersionedSecretProvider versionProvider)
            {
                if (MemoryCache.TryGetValue(secretName, out Secret[] cachedSecrets) 
                    && cachedSecrets.Length >= amountOfVersions)
                {
                    return cachedSecrets.Take(amountOfVersions);
                }

                Task<IEnumerable<Secret>> getSecretsAsync = versionProvider.GetSecretsAsync(secretName, amountOfVersions);
                IEnumerable<Secret> secrets = getSecretsAsync is null ? null : await getSecretsAsync;
                Secret[] secretsArray = secrets.ToArray();
                
                MemoryCache.Set(secretName, secretsArray, CacheEntry);
                return secretsArray;
            }

            Secret secret = await GetSecretAsync(secretName);
            return new[] { secret };
        }

        /// <summary>
        /// Removes the secret with the given <paramref name="secretName"/> from the cache;
        /// so the next time <see cref="GetSecretAsync(string)"/> is called, a new version of the secret will be added back to the cache.
        /// </summary>
        /// <param name="secretName">The name of the secret that should be removed from the cache.</param>
        public Task InvalidateSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to invalidate the cached secret");

            MemoryCache.Remove(secretName);
            return Task.CompletedTask;
        }
    }
}
