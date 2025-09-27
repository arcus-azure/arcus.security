using System;
using Arcus.Security.Core.Caching.Configuration;
using Microsoft.Extensions.Caching.Memory;

namespace Arcus.Security.Core.Caching
{
    /// <summary>
    /// Provide extensions for more fluent/easy composition of adding caching to retrieve Azure Key Vault secrets with the <see cref="CachedSecretProvider"/>.
    /// </summary>
    public static class SecretProviderCachingExtensions
    {
        /// <summary>
        /// Creates an <see cref="ICachedSecretProvider" /> instance that will use <see cref="IMemoryCache"/> to get SecretValues from the passed <paramref name="secretProvider"/>.
        /// </summary>
        /// <param name="secretProvider">An instantiated <see cref="ISecretProvider" /> that will only be called if the value is not cached</param>
        /// <param name="cachingDuration">The duration to cache secrets in memory</param>
        /// <param name="memoryCache">Optional <see cref="IMemoryCache" /> that can be used for caching.  Defaults to a <see cref="MemoryCache" /> instance</param>
        /// <returns>A secret provider that caches values</returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> or <paramref name="memoryCache"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="cachingDuration"/> is not a positive time duration.</exception>
        [Obsolete("Will be removed in v3.0 in favor of placing the secret caching on the secret store itself")]
        public static ICachedSecretProvider WithCaching(this ISecretProvider secretProvider, TimeSpan cachingDuration, IMemoryCache memoryCache)
        {
            if (secretProvider is null)
            {
                throw new ArgumentNullException(nameof(secretProvider), "Requires a secret provider instance to include caching while retrieving secrets");
            }

            if (cachingDuration < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(cachingDuration), "Requires a positive time duration in which the caching should take place");
            }

            if (memoryCache is null)
            {
                throw new ArgumentNullException(nameof(memoryCache), "Requires a memory caching implementation to include caching while retrieving secrets");
            }

            return new CachedSecretProvider(secretProvider, new CacheConfiguration(cachingDuration), memoryCache);
        }

        /// <summary>
        /// Creates an <see cref="ICachedSecretProvider" /> instance that will use a default <see cref="IMemoryCache"/> implementation
        /// to get SecretValues from the passed <paramref name="secretProvider"/>.
        /// </summary>
        /// <param name="secretProvider">An instantiated <see cref="ISecretProvider" /> that will only be called if the value is not cached</param>
        /// <param name="cachingDuration">The duration to cache secrets in memory</param>
        /// <returns>A secret provider that caches values</returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="cachingDuration"/> is not a positive time duration.</exception>
        [Obsolete("Will be removed in v3.0 in favor of placing the secret caching on the secret store itself")]
        public static ICachedSecretProvider WithCaching(this ISecretProvider secretProvider, TimeSpan cachingDuration)
        {
            if (secretProvider is null)
            {
                throw new ArgumentNullException(nameof(secretProvider), "Requires a secret provider instance to include caching while retrieving secrets");
            }

            if (cachingDuration < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(cachingDuration), cachingDuration, "Requires a positive time duration in which the caching should take place");
            }

            return new CachedSecretProvider(secretProvider, new CacheConfiguration(cachingDuration));
        }

        /// <summary>
        /// Creates an <see cref="ICachedSecretProvider" /> instance that will use a default <see cref="IMemoryCache"/> implementation
        /// to get SecretValues from the passed <paramref name="secretProvider"/>.
        /// </summary>
        /// <param name="secretProvider">An instantiated <see cref="ISecretProvider" /> that will only be called if the value is not cached</param>
        /// <returns>A secret provider that caches values</returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of placing the secret caching on the secret store itself")]
        public static ICachedSecretProvider WithCaching(this ISecretProvider secretProvider)
        {
            if (secretProvider is null)
            {
                throw new ArgumentNullException(nameof(secretProvider), "Requires a secret provider instance to include caching while retrieving secrets");
            }

            return new CachedSecretProvider(secretProvider);
        }
    }
}